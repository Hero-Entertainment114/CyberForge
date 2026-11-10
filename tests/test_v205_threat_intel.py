from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from server import create_handler
from server_core import AIService, Store
import threat_intel


def nowz():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def stix_indicator(object_id="indicator--11111111-1111-4111-8111-111111111111", pattern="[ipv4-addr:value = '198.51.100.7']", **extra):
    return {"type": "indicator", "spec_version": "2.1", "id": object_id,
            "created": nowz(), "modified": nowz(), "pattern_type": "stix",
            "pattern": pattern, "valid_from": nowz(), "confidence": 90,
            "name": "unit-test indicator", **extra}


class ThreatIntelUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "server.sqlite3"))
        threat_intel.initialize(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def feed(self, feed_type="stix_bundle", **extra):
        return threat_intel.create_feed(self.store, {"name": "Test feed", "feed_type": feed_type, **extra}, "tester")["feed_id"]

    def test_builtin_feeds_are_seeded(self):
        feeds = {x["feed_id"]: x for x in threat_intel.list_feeds(self.store)}
        self.assertIn("cisa-kev", feeds)
        self.assertIn("first-epss", feeds)
        self.assertFalse(feeds["cisa-kev"]["enabled"])

    def test_normalize_ipv4_and_ipv6(self):
        self.assertEqual(threat_intel.normalize_ioc("ip", "192.0.2.1"), ("ipv4", "192.0.2.1"))
        self.assertEqual(threat_intel.normalize_ioc("ipv6", "2001:0db8::1"), ("ipv6", "2001:db8::1"))

    def test_normalize_idna_domain(self):
        self.assertEqual(threat_intel.normalize_ioc("domain", "BÜCHER.example."), ("domain", "xn--bcher-kva.example"))

    def test_normalize_sha256_and_cve(self):
        self.assertEqual(threat_intel.normalize_ioc("sha256", "A" * 64), ("sha256", "a" * 64))
        self.assertEqual(threat_intel.normalize_ioc("cve", "cve-2025-12345"), ("cve", "CVE-2025-12345"))

    def test_reject_invalid_ip(self):
        with self.assertRaisesRegex(ValueError, "threat_ioc_invalid"):
            threat_intel.normalize_ioc("ip", "999.1.1.1")

    def test_reject_wildcard_domain(self):
        with self.assertRaisesRegex(ValueError, "threat_ioc_invalid"):
            threat_intel.normalize_ioc("domain", "*.example.com")

    def test_reject_url_credentials_and_secret_query(self):
        for value in ("https://user:pass@example.com/a", "https://example.com/?token=secret", "https://example.com/?api_key=secret"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                threat_intel.normalize_ioc("url", value)

    def test_url_ipv6_literal_is_normalized_with_brackets(self):
        self.assertEqual(threat_intel.normalize_ioc("url", "https://[2001:4860:4860::8888]/a"),
                         ("url", "https://[2001:4860:4860::8888]/a"))

    def test_reject_invalid_hash_and_type(self):
        with self.assertRaises(ValueError): threat_intel.normalize_ioc("sha256", "abc")
        with self.assertRaisesRegex(ValueError, "threat_ioc_type_unsupported"):
            threat_intel.normalize_ioc("email", "a@example.com")

    def test_feed_url_requires_https_and_allowlist(self):
        with self.assertRaisesRegex(ValueError, "threat_feed_https_required"):
            threat_intel._validate_remote_url("http://www.cisa.gov/feed")
        with self.assertRaisesRegex(ValueError, "threat_feed_host_not_allowlisted"):
            threat_intel._validate_remote_url("https://untrusted.invalid/feed")

    def test_feed_url_rejects_query_credentials(self):
        with self.assertRaisesRegex(ValueError, "threat_feed_url_invalid"):
            threat_intel._validate_remote_url("https://www.cisa.gov/feed?api_key=secret")

    def test_create_feed_rejects_non_boolean_enabled(self):
        with self.assertRaisesRegex(ValueError, "threat_feed_invalid"):
            self.feed(enabled="false")

    def test_create_feed_rejects_url_for_uploaded_feed(self):
        with self.assertRaisesRegex(ValueError, "threat_feed_url_not_used"):
            self.feed(url="https://example.com/feed")

    def test_create_taxii_feed_allowlisted_host(self):
        with patch.dict(os.environ, {"CF_THREAT_INTEL_ALLOWED_HOSTS": "taxii.example"}):
            feed_id = self.feed("taxii21", url="https://taxii.example/taxii/", collection_id="c1")
            self.assertTrue(any(x["feed_id"] == feed_id for x in threat_intel.list_feeds(self.store)))

    def test_stix_parses_supported_observables(self):
        bundle = {"type": "bundle", "objects": [
            stix_indicator(pattern="[ipv4-addr:value = '198.51.100.7' OR domain-name:value = 'bad.example']"),
            stix_indicator("indicator--22222222-2222-4222-8222-222222222222", "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"),
        ]}
        indicators, rels, ignored = threat_intel.parse_stix_bundle(bundle)
        actual = {(x.get("ioc_type"), x.get("value")) for x in indicators if "ioc_type" in x}
        self.assertEqual(actual, {("ipv4", "198.51.100.7"), ("domain", "bad.example"), ("sha256", "a" * 64)})
        self.assertEqual(ignored, 0)

    def test_stix_rejects_wrong_bundle_and_object_limit(self):
        with self.assertRaisesRegex(ValueError, "threat_stix_bundle_invalid"):
            threat_intel.parse_stix_bundle({"objects": []})
        with patch.object(threat_intel, "MAX_IMPORT_OBJECTS", 1):
            with self.assertRaisesRegex(ValueError, "threat_stix_object_limit"):
                threat_intel.parse_stix_bundle({"type": "bundle", "objects": [{}, {}]})

    def test_stix_negated_patterns_are_not_positive_indicators(self):
        negative = stix_indicator("indicator--33333333-3333-4333-8333-333333333333", "[not ipv4-addr:value = '198.51.100.7']")
        indicators, _, ignored = threat_intel.parse_stix_bundle({"type": "bundle", "objects": [negative]})
        self.assertEqual(ignored, 1)
        self.assertFalse(any(x.get("ioc_type") for x in indicators))

    def test_stix_ignores_revoked_and_unsupported_patterns(self):
        revoked = stix_indicator("indicator--33333333-3333-4333-8333-333333333333", revoked=True)
        bad = stix_indicator("indicator--44444444-4444-4444-8444-444444444444", pattern="[process:name = 'bad']")
        indicators, _, ignored = threat_intel.parse_stix_bundle({"type": "bundle", "objects": [revoked, bad]})
        self.assertEqual(ignored, 2)
        self.assertTrue(any("_revoke_object_id" in x for x in indicators))

    def test_stix_import_and_local_lookup(self):
        feed_id = self.feed()
        result = threat_intel.import_stix(self.store, feed_id, {"type": "bundle", "objects": [stix_indicator()]}, "tester")
        self.assertEqual(result["added"], 1)
        found = threat_intel.lookup(self.store, "ip", "198.51.100.7")
        self.assertTrue(found["matched"])
        self.assertEqual(found["matches"][0]["confidence"], 90)
        self.assertIn("not resolved", found["note"])

    def test_lookup_cache_hit(self):
        feed_id = self.feed()
        threat_intel.import_stix(self.store, feed_id, {"type": "bundle", "objects": [stix_indicator()]}, "tester")
        self.assertEqual(threat_intel.lookup(self.store, "ip", "198.51.100.7")["cache"], "miss")
        self.assertEqual(threat_intel.lookup(self.store, "ip", "198.51.100.7")["cache"], "hit")

    def test_import_invalidates_negative_cache(self):
        self.assertFalse(threat_intel.lookup(self.store, "ip", "198.51.100.7")["matched"])
        feed_id = self.feed()
        threat_intel.import_stix(self.store, feed_id, {"type": "bundle", "objects": [stix_indicator()]}, "tester")
        self.assertTrue(threat_intel.lookup(self.store, "ip", "198.51.100.7")["matched"])

    def test_json_ioc_import_and_dedup(self):
        feed_id = self.feed("json_iocs")
        record = {"ioc_type": "domain", "value": "malware.example", "confidence": 80}
        self.assertEqual(threat_intel.import_json_iocs(self.store, feed_id, [record], "tester")["added"], 1)
        self.assertEqual(threat_intel.import_json_iocs(self.store, feed_id, [record], "tester")["updated"], 1)
        self.assertTrue(threat_intel.lookup(self.store, "domain", "MALWARE.example")["matched"])

    def test_import_rejects_disabled_feed(self):
        feed_id = self.feed("json_iocs", enabled=False)
        with self.assertRaisesRegex(ValueError, "threat_feed_disabled"):
            threat_intel.import_json_iocs(self.store, feed_id, [{"ioc_type": "ip", "value": "192.0.2.2"}], "tester")

    def test_stix_revocation_invalidates_existing_ioc(self):
        feed_id = self.feed()
        object_id = "indicator--55555555-5555-4555-8555-555555555555"
        threat_intel.import_stix(self.store, feed_id, {"type": "bundle", "objects": [stix_indicator(object_id)]}, "tester")
        self.assertTrue(threat_intel.lookup(self.store, "ip", "198.51.100.7")["matched"])
        revoked = stix_indicator(object_id, revoked=True)
        threat_intel.import_stix(self.store, feed_id, {"type": "bundle", "objects": [revoked]}, "tester")
        self.assertFalse(threat_intel.lookup(self.store, "ip", "198.51.100.7")["matched"])

    def test_invalid_validity_timestamps_are_ignored(self):
        feed_id = self.feed("json_iocs")
        result = threat_intel.import_json_iocs(self.store, feed_id, [{"ioc_type": "ip", "value": "203.0.113.11", "valid_from": "not-a-time"}], "tester")
        self.assertEqual(result["ignored"], 1)
        self.assertFalse(threat_intel.lookup(self.store, "ip", "203.0.113.11")["matched"])

    def test_valid_from_is_respected(self):
        feed_id = self.feed("json_iocs")
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        threat_intel.import_json_iocs(self.store, feed_id, [{"ioc_type": "ip", "value": "203.0.113.8", "valid_from": future}], "tester")
        self.assertFalse(threat_intel.lookup(self.store, "ip", "203.0.113.8")["matched"])
        self.assertEqual(threat_intel.list_iocs(self.store), [])

    def test_expired_ioc_is_hidden_from_list_and_lookup(self):
        feed_id = self.feed("json_iocs")
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        threat_intel.import_json_iocs(self.store, feed_id, [{"ioc_type": "ip", "value": "203.0.113.9", "valid_until": past}], "tester")
        self.assertFalse(threat_intel.lookup(self.store, "ip", "203.0.113.9")["matched"])
        self.assertEqual(threat_intel.list_iocs(self.store), [])

    def test_cisa_kev_sync_imports_cves(self):
        threat_intel.set_feed_enabled(self.store, "cisa-kev", True, "tester")
        payload = {"vulnerabilities": [{"cveID": "CVE-2025-12345", "vulnerabilityName": "Test CVE",
                                         "vendorProject": "Acme", "product": "Widget", "dateAdded": "2025-01-01"}]}
        with patch.object(threat_intel, "_request", return_value=(200, {"ETag": "e1"}, json.dumps(payload).encode())):
            result = threat_intel.sync_feed(self.store, "cisa-kev", "tester")
        self.assertEqual(result["added"], 1)
        self.assertTrue(threat_intel.lookup(self.store, "cve", "cve-2025-12345")["matched"])

    def test_cisa_kev_304_not_modified(self):
        threat_intel.set_feed_enabled(self.store, "cisa-kev", True, "tester")
        with patch.object(threat_intel, "_request", return_value=(304, {}, b"")):
            result = threat_intel.sync_feed(self.store, "cisa-kev", "tester")
        self.assertTrue(result["not_modified"])

    def test_epss_lookup_uses_official_api_shape(self):
        payload = {"data": [{"cve": "CVE-2025-12345", "epss": "0.1234", "percentile": "0.9", "date": "2025-01-01"}]}
        with patch.object(threat_intel, "_request", return_value=(200, {}, json.dumps(payload).encode())) as req:
            result = threat_intel.epss_lookup(["cve-2025-12345"])
        self.assertEqual(result["results"][0]["epss"], 0.1234)
        self.assertIn("cve=CVE-2025-12345", req.call_args.args[0])

    def test_epss_lookup_uses_local_cache(self):
        payload = {"data": [{"cve": "CVE-2025-12345", "epss": "0.1234", "percentile": "0.9", "date": "2025-01-01"}]}
        with patch.object(threat_intel, "_request", return_value=(200, {}, json.dumps(payload).encode())) as req:
            first = threat_intel.epss_lookup(["CVE-2025-12345"], self.store)
            second = threat_intel.epss_lookup(["CVE-2025-12345"], self.store)
        self.assertEqual(req.call_count, 1)
        self.assertEqual(first["results"], second["results"])
        self.assertEqual(second["cache"], "hit")

    def test_epss_batch_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "threat_epss_batch_invalid"):
            threat_intel.epss_lookup([f"CVE-2025-{10000+i}" for i in range(51)])

    def test_taxii_discovers_and_paginates_same_host(self):
        with patch.dict(os.environ, {"CF_THREAT_INTEL_ALLOWED_HOSTS": "taxii.example"}):
            feed_id = self.feed("taxii21", url="https://taxii.example/discovery/", collection_id="c1")
            feed = threat_intel._feed(self.store, feed_id)
            page1 = {"objects": [stix_indicator("indicator--66666666-6666-4666-8666-666666666666")], "next": "cursor-2"}
            page2 = {"objects": [stix_indicator("indicator--77777777-7777-4777-8777-777777777777", "[domain-name:value = 'taxii-bad.example']")]}
            replies = [
                (200, {}, json.dumps({"api_roots": ["https://taxii.example/api/"]}).encode()),
                (200, {}, json.dumps({"collections": [{"id": "c1"}]}).encode()),
                (200, {}, json.dumps(page1).encode()),
                (200, {}, json.dumps(page2).encode()),
            ]
            with patch.object(threat_intel, "_request", side_effect=replies) as req:
                bundle, _ = threat_intel._taxii_objects(dict(feed), json.loads(feed["config_json"]))
            self.assertEqual(len(bundle["objects"]), 2)
            self.assertEqual(req.call_count, 4)

    def test_taxii_rejects_cross_host_api_root(self):
        with patch.dict(os.environ, {"CF_THREAT_INTEL_ALLOWED_HOSTS": "taxii.example,evil.example"}):
            discovery = (200, {}, json.dumps({"api_roots": ["https://evil.example/api/"]}).encode())
            with patch.object(threat_intel, "_request", return_value=discovery):
                with self.assertRaisesRegex(ValueError, "threat_taxii_cross_host_rejected"):
                    threat_intel._taxii_objects({"url": "https://taxii.example/discovery/"}, {})

    def test_taxii_rejects_repeated_pagination_token(self):
        with patch.dict(os.environ, {"CF_THREAT_INTEL_ALLOWED_HOSTS": "taxii.example"}):
            feed_id = self.feed("taxii21", url="https://taxii.example/discovery/", collection_id="c1")
            feed = threat_intel._feed(self.store, feed_id)
            payloads = [
                (200, {}, json.dumps({"api_roots": ["https://taxii.example/api/"]}).encode()),
                (200, {}, json.dumps({"collections": [{"id": "c1"}]}).encode()),
                (200, {}, json.dumps({"objects": [], "next": "same"}).encode()),
                (200, {}, json.dumps({"objects": [], "next": "same"}).encode()),
            ]
            with patch.object(threat_intel, "_request", side_effect=payloads):
                with self.assertRaisesRegex(ValueError, "threat_feed_format_invalid"):
                    threat_intel._taxii_objects(dict(feed), json.loads(feed["config_json"]))

    def test_summary_reports_supported_ioc_types(self):
        result = threat_intel.summary(self.store)
        self.assertIn("sha256", result["supported_types"])
        self.assertGreaterEqual(result["feeds_total"], 2)

    def test_summary_excludes_iocs_not_yet_valid(self):
        feed_id = self.feed("json_iocs")
        future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        threat_intel.import_json_iocs(self.store, feed_id, [{"ioc_type": "ip", "value": "203.0.113.44", "valid_from": future}], "tester")
        result = threat_intel.summary(self.store)
        self.assertEqual(result["active_iocs"], 0)
        self.assertEqual(result["by_type"], [])

    def test_cisa_invalid_json_has_format_error_and_status(self):
        threat_intel.set_feed_enabled(self.store, "cisa-kev", True, "tester")
        with patch.object(threat_intel, "_request", return_value=(200, {}, b"not-json")):
            with self.assertRaisesRegex(ValueError, "threat_feed_format_invalid"):
                threat_intel.sync_feed(self.store, "cisa-kev", "tester")
        feed = threat_intel._feed(self.store, "cisa-kev")
        self.assertEqual(feed["last_status"], "error")
        self.assertEqual(feed["last_error"], "threat_feed_format_invalid")

    def test_ai_analyst_prompt_includes_threat_intel_with_caveat(self):
        from security_intelligence import build_ai_messages
        messages = build_ai_messages({"incident": {"incident_id": "inc-test"},
            "threat_intelligence": {"matched_indicators": 1, "matches": [{"type": "cve", "value": "CVE-2025-12345", "feed_name": "CISA KEV", "confidence": 100}]}})
        self.assertIn("CVE-2025-12345", messages[1]["content"])
        self.assertIn("not proof of compromise", messages[0]["content"])


class ThreatIntelAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.data = cls.tmp.name
        cls.store = Store(os.path.join(cls.data, "server.sqlite3"))
        cls.tokens = {role: cls.store.create_token("v205-" + role, role)["token"]
                      for role in ("admin", "operator", "analyst", "viewer", "sensor")}
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(cls.store, AIService(cls.store), cls.data))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(timeout=3); cls.tmp.cleanup()

    def request(self, role, method, path, body=None):
        import urllib.error, urllib.request
        raw = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": "Bearer " + self.tokens[role], "Accept-Language": "en"}
        if raw is not None: headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=raw, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=4) as res: return res.status, json.loads(res.read())
        except urllib.error.HTTPError as exc: return exc.code, json.loads(exc.read())

    def test_viewer_can_read_threat_intel_overview(self):
        status, body = self.request("viewer", "GET", "/api/v205/threat-intel/overview")
        self.assertEqual(status, 200); self.assertIn("active_iocs", body)

    def test_sensor_cannot_read_threat_intel(self):
        status, body = self.request("sensor", "GET", "/api/v205/threat-intel/overview")
        self.assertEqual(status, 403); self.assertEqual(body["error"]["code"], "forbidden")

    def test_analyst_cannot_create_feed(self):
        status, body = self.request("analyst", "POST", "/api/v205/threat-intel/feeds", {"name": "x", "feed_type": "json_iocs"})
        self.assertEqual(status, 403)

    def test_operator_can_create_feed_and_import_ioc(self):
        status, body = self.request("operator", "POST", "/api/v205/threat-intel/feeds", {"name": "API feed", "feed_type": "json_iocs"})
        self.assertEqual(status, 201)
        feed_id = body["feed"]["feed_id"]
        status, imported = self.request("operator", "POST", "/api/v205/threat-intel/import/json", {
            "feed_id": feed_id, "indicators": [{"ioc_type": "domain", "value": "api-malware.example", "confidence": 88}]})
        self.assertEqual(status, 202); self.assertEqual(imported["result"]["added"], 1)
        status, found = self.request("viewer", "GET", "/api/v205/threat-intel/lookup?type=domain&value=api-malware.example")
        self.assertEqual(status, 200); self.assertTrue(found["matched"])

    def test_viewer_cannot_manage_feed(self):
        status, body = self.request("viewer", "POST", "/api/v205/threat-intel/feeds", {"name": "x", "feed_type": "json_iocs"})
        self.assertEqual(status, 403)

    def test_analyst_can_batch_enrich_but_viewer_cannot(self):
        status, body = self.request("analyst", "POST", "/api/v205/threat-intel/lookup/batch", {"indicators": [{"type": "ip", "value": "203.0.113.10"}]})
        self.assertEqual(status, 200); self.assertEqual(len(body["results"]), 1)
        status, body = self.request("viewer", "POST", "/api/v205/threat-intel/lookup/batch", {"indicators": [{"type": "ip", "value": "203.0.113.10"}]})
        self.assertEqual(status, 403)

    def test_incident_enrichment_matches_local_ioc(self):
        from security_ops import initialize as security_initialize
        security_initialize(self.store)
        incident_id = "inc_threat_test_0001"
        timestamp = nowz()
        with self.store.lock, self.store.connect() as con:
            con.execute("INSERT INTO security_incidents(incident_id,fingerprint,status,severity,title,category,first_seen,last_seen,event_count,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (incident_id, "fp-threat-v205", "open", "high", "Threat test incident", "network", timestamp, timestamp, 1, timestamp, timestamp))
            con.execute("INSERT INTO security_events(event_id,incident_id,source,source_event_id,observed_at,received_at,severity,category,title,host,node_id,src_ip,dst_ip,src_port,dst_port,process_name,rule_id,details_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        ("evt-threat-v205", incident_id, "suricata", "event-threat-v205", timestamp, timestamp, "high", "alert", "Known indicator contact", "node-threat", None, "198.51.100.77", "203.0.113.77", 12345, 443, "curl", "ET-TEST", "{}"))
        status, created = self.request("operator", "POST", "/api/v205/threat-intel/feeds", {"name": "Incident IOC feed", "feed_type": "json_iocs"})
        self.assertEqual(status, 201)
        status, imported = self.request("operator", "POST", "/api/v205/threat-intel/import/json", {"feed_id": created["feed"]["feed_id"], "indicators": [{"ioc_type": "ip", "value": "198.51.100.77", "confidence": 95}]})
        self.assertEqual(status, 202)
        status, result = self.request("viewer", "GET", f"/api/v205/threat-intel/incidents/{incident_id}/enrichment")
        self.assertEqual(status, 200)
        self.assertEqual(result["matched_indicators"], 1)
        self.assertEqual(result["matches"][0]["value"], "198.51.100.77")

    def test_api_errors_are_localized(self):
        status, body = self.request("operator", "POST", "/api/v205/threat-intel/feeds", {"name": "x", "feed_type": "bad"})
        self.assertEqual(status, 400)
        self.assertIn("not supported", body["error"]["message"])
        import urllib.error, urllib.request
        req = urllib.request.Request(self.base + "/api/v205/threat-intel/feeds", data=json.dumps({"name":"x","feed_type":"bad"}).encode(), method="POST",
                                     headers={"Authorization":"Bearer "+self.tokens["operator"],"Accept-Language":"vi","Content-Type":"application/json"})
        try:
            urllib.request.urlopen(req, timeout=4)
            self.fail("expected HTTPError")
        except urllib.error.HTTPError as exc:
            payload = json.loads(exc.read())
            self.assertIn("chưa được hỗ trợ", payload["error"]["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
