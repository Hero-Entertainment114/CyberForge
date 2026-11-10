#!/usr/bin/env python3
"""Deterministic static release checks for CyberForge Server Edition."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)

class HTMLAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: list[str] = []
        self.scripts: list[str] = []
        self._inline = False
    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "script":
            self._inline = not bool(values.get("src"))
            if self._inline:
                self.scripts.append("")
    def handle_endtag(self, tag):
        if tag == "script":
            self._inline = False
    def handle_data(self, data):
        if self._inline and self.scripts:
            self.scripts[-1] += data


def run(command: list[str], *, check=True):
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=check)


def main() -> int:
    checks = []
    # Python syntax without importing or executing application modules.
    py_files = [p for p in ROOT.rglob("*.py") if "__pycache__" not in p.parts]
    for path in py_files:
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    checks.append(f"python_syntax={len(py_files)} files")

    manifest = json.loads((ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
    edition = json.loads((ROOT / "edition.json").read_text(encoding="utf-8"))
    version = (ROOT / "VERSION.txt").read_text(encoding="utf-8").strip()
    if not version or manifest.get("version") != version or edition.get("version") != version:
        raise SystemExit("Version mismatch between VERSION.txt, manifest and edition.json")
    if (ROOT / "RELEASE_CHANNEL.txt").read_text(encoding="utf-8").strip() != "official-stable":
        raise SystemExit("Release channel file is not official-stable")
    if manifest.get("release_channel") != "official-stable" or manifest.get("official_stable") is not True:
        raise SystemExit("RELEASE_MANIFEST.json does not identify an official-stable release")
    if edition.get("release_channel") != "official-stable":
        raise SystemExit("edition.json release channel mismatch")
    discovered = int(manifest.get("tests_discovered", -1))
    passed = int(manifest.get("tests_passed", -1))
    skipped = int(manifest.get("tests_skipped", -1))
    modules = int(manifest.get("test_modules", -1))
    actual_modules = len(list((ROOT / "tests").glob("test_*.py")))
    if discovered != passed + skipped or modules != actual_modules:
        raise SystemExit("Release test counts/module count are inconsistent in RELEASE_MANIFEST.json")
    checks.append(f"version_consistency={version}")
    checks.append(f"official_stable_metadata=valid ({discovered} tests, {modules} modules)")

    html = HTMLAudit()
    html.feed((ROOT / "static/index.html").read_text(encoding="utf-8"))
    dupes = sorted({x for x in html.ids if html.ids.count(x) > 1})
    if dupes:
        raise SystemExit(f"Duplicate HTML IDs: {dupes}")
    checks.append(f"html_ids={len(html.ids)} unique")

    node = shutil.which("node")
    if node:
        with tempfile.TemporaryDirectory(prefix="cf-release-") as tmp:
            for i, script in enumerate(html.scripts):
                target = Path(tmp) / f"inline-{i}.js"
                target.write_text(script, encoding="utf-8")
                run([node, "--check", str(target)])
        checks.append(f"javascript_syntax={len(html.scripts)} inline scripts")
    else:
        checks.append("javascript_syntax=SKIPPED (node not installed)")

    bash = shutil.which("bash")
    scripts = sorted((ROOT / "deploy").rglob("*.sh")) + sorted((ROOT / "tools").rglob("*.sh"))
    if bash:
        for script in scripts:
            run([bash, "-n", str(script)])
        checks.append(f"shell_syntax={len(scripts)} scripts")
    else:
        checks.append("shell_syntax=SKIPPED (bash not installed)")

    if "ai_control.py" not in {p.name for p in ROOT.glob("*.py")}:
        raise SystemExit("Missing AI control plane module")
    for endpoint in ("/api/v201/ai/models", "/api/v201/ai/queue", "/api/v201/ai/gpu", "/api/v201/ai/jobs"):
        if endpoint not in (ROOT / "server.py").read_text(encoding="utf-8"):
            raise SystemExit(f"Missing API route marker: {endpoint}")
    if "/api/v202/cluster" not in (ROOT / "server.py").read_text(encoding="utf-8"):
        raise SystemExit("Missing distributed cluster status API")
    security_server = (ROOT / "server.py").read_text(encoding="utf-8")
    for endpoint in ("/api/v203/security/sources", "/api/v203/security/overview",
                     "/api/v203/security/events", "/api/v203/security/incidents",
                     "/api/v203/security/ingest/", "/api/v203/security/playbooks/plan",
                     "/api/v204/security/sources", "/api/v204/security/ingest/",
                     "/api/v204/security/mitre/summary", "/api/v204/security/incidents/", "/ai-analysis"):
        if endpoint not in security_server:
            raise SystemExit(f"Missing Security Operations API route marker: {endpoint}")
    for required in ("security_ops.py", "security_intelligence.py", "tools/ingest_jsonl.py",
                     "tools/tail_jsonl.py", "docs/SECURITY_OPERATIONS.md", "docs/SECURITY_INTELLIGENCE.md",
                     "deploy/systemd/cyberforge-security-tail@.service.example",
                     "migrations/0003_security_operations.sql", "migrations/0004_security_intelligence.sql",
                     "tests/test_security_ops.py", "tests/test_security_shipper.py",
                     "tests/test_v204_security_intelligence.py", "tests/test_v204_telemetry_tail.py",
                     "tests/test_v204_security_api.py"):
        if not (ROOT / required).exists():
            raise SystemExit(f"Missing Security Operations release file: {required}")
    security_module = (ROOT / "security_ops.py").read_text(encoding="utf-8")
    if "def list_events(" not in security_module or "SOURCES = (\"wazuh\", \"suricata\", \"zeek\", \"falco\", \"trivy\", \"osquery\")" not in security_module:
        raise SystemExit("Missing normalized security event source/list support")
    if '\"sensor\": [\"security:ingest\"]' not in (ROOT / "server_core.py").read_text(encoding="utf-8"):
        raise SystemExit("Missing least-privilege sensor role")
    core = (ROOT / "server_core.py").read_text(encoding="utf-8")
    if "def claim_workflow(" not in core or "def renew_workflow(" not in core or "workflow_execution_lease_lost" not in core:
        raise SystemExit("Missing distributed workflow execution lease controls")
    for required in ("distributed.py", "requirements-distributed.txt", "docs/DISTRIBUTED_DEPLOYMENT.md", "migrations/0002_postgres_distributed.sql"):
        if not (ROOT / required).exists():
            raise SystemExit(f"Missing distributed release file: {required}")
    checks.append("ai_control_api=present")
    checks.append("distributed_storage_and_queue=present")
    checks.append("distributed_workflow_leases=present")
    security_intel = (ROOT / "security_intelligence.py").read_text(encoding="utf-8")
    tailer = (ROOT / "tools/tail_jsonl.py").read_text(encoding="utf-8")
    if "def incident_analysis(" not in security_intel or "def correlate_incident(" not in security_intel:
        raise SystemExit("Missing security intelligence correlation/analysis")
    if "def poll_once(" not in tailer or "instance_lock_path" not in tailer:
        raise SystemExit("Missing continuous telemetry checkpoint/lock logic")
    checks.append("security_operations_ingest_and_events=present")
    checks.append("security_intelligence_and_mitre_candidate_analysis=present")
    checks.append("continuous_jsonl_tailer_and_checkpoint=present")
    checks.append("sensor_least_privilege=present")

    # Threat Intelligence: ensure the bounded feed/IOC subsystem is present and versioned.
    threat_server = (ROOT / "server.py").read_text(encoding="utf-8")
    threat_module = (ROOT / "threat_intel.py").read_text(encoding="utf-8")
    for endpoint in ("/api/v205/threat-intel/overview", "/api/v205/threat-intel/feeds",
                     "/api/v205/threat-intel/iocs", "/api/v205/threat-intel/lookup",
                     "/api/v205/threat-intel/import/stix", "/api/v205/threat-intel/import/json",
                     "/api/v205/threat-intel/epss/lookup"):
        if endpoint not in threat_server:
            raise SystemExit(f"Missing Threat Intelligence API route marker: {endpoint}")
    for required in ("threat_intel.py", "docs/THREAT_INTELLIGENCE.md", "migrations/0005_threat_intelligence.sql",
                     "tests/test_v205_threat_intel.py", "RELEASE_NOTES_2.0.5.md", "TEST_RESULTS_2.0.5.md"):
        if not (ROOT / required).exists():
            raise SystemExit(f"Missing Threat Intelligence release file: {required}")
    for required_function in ("def parse_stix_bundle(", "def _taxii_objects(", "def sync_feed(", "def lookup_many(", "def enrich_incident(", "def epss_lookup("):
        if required_function not in threat_module:
            raise SystemExit(f"Missing Threat Intelligence implementation: {required_function}")
    if "CF_THREAT_INTEL_ALLOWED_HOSTS" not in (ROOT / ".env.example").read_text(encoding="utf-8"):
        raise SystemExit("Missing Threat Intelligence host allowlist configuration example")
    if '"threatintel:manage"' not in core or '"threatintel:enrich"' not in core:
        raise SystemExit("Missing Threat Intelligence role scopes")
    checks.append("threat_intelligence_ioc_stix_taxii_epss_api=present")
    checks.append("threat_intelligence_docs_migration_and_tests=present")

    # Official Stable v2.1.0: versioned data-only detection rules and transactional installer.
    if version != "2.1.0":
        raise SystemExit("This official-stable release check expects VERSION.txt=2.1.0")
    if (ROOT / "RELEASE_CHANNEL.txt").read_text(encoding="utf-8").strip() != "official-stable":
        raise SystemExit("Release channel is not official-stable")
    detection_server = (ROOT / "server.py").read_text(encoding="utf-8")
    for endpoint in ("/api/v210/detection/overview", "/api/v210/detection/rules",
                     "/api/v210/detection/matches", "/api/v210/detection/rules/"):
        if endpoint not in detection_server:
            raise SystemExit(f"Missing Detection Engineering API route marker: {endpoint}")
    detection_module = (ROOT / "detection_engine.py").read_text(encoding="utf-8")
    for function in ("def create_draft(", "def revise_draft(", "def validate_rule(",
                     "def test_rule(", "def publish_rule(", "def retire_rule(",
                     "def rollback_to_version(", "def evaluate_in_transaction("):
        if function not in detection_module:
            raise SystemExit(f"Missing Detection Engineering implementation: {function}")
    for required in ("detection_engine.py", "docs/DETECTION_ENGINEERING.md",
                     "migrations/0006_detection_engineering.sql", "tests/test_detection_engine.py",
                     "tests/test_official_release.py", "RELEASE_NOTES_2.1.0.md",
                     "TEST_RESULTS_2.1.0.md", "docs/UPGRADE_BACKUP_RESTORE.md",
                     "deploy/install.sh", "deploy/systemd/cyberforge-server.service",
                     "RELEASE_CHANNEL.txt"):
        if not (ROOT / required).exists():
            raise SystemExit(f"Missing Official Stable release file: {required}")
    install_script = (ROOT / "deploy/install.sh").read_text(encoding="utf-8")
    for marker in ("mktemp -d", "backup --output", "verify-backup", "preflight",
                   "mv -Tf", "rolling back the active release", "HEALTH_OK",
                   "SERVICE_ENABLED_STATE", "systemctl daemon-reload"):
        if marker not in install_script:
            raise SystemExit(f"Official installer missing required transaction marker: {marker}")
    service_unit = (ROOT / "deploy/systemd/cyberforge-server.service").read_text(encoding="utf-8")
    if "/opt/cyberforge-server/current/.venv/bin/python" not in service_unit:
        raise SystemExit("systemd service does not use the staged release virtual environment")
    if '"detection:publish"' not in core or '"detection:read"' not in core:
        raise SystemExit("Detection Engineering RBAC scopes missing")
    if 'CF_DETECTION_REQUIRE_TWO_PERSON=1' not in (ROOT / ".env.example").read_text(encoding="utf-8"):
        raise SystemExit("Two-person detection publishing default missing from .env.example")
    checks.append("detection_engineering_lifecycle_api_rbac_migration=present")
    checks.append("official_stable_staged_installer_backup_preflight_rollback=present")
    checks.append("official_stable_channel_and_release_docs=present")

    print("CyberForge Server Edition release checks: PASS")
    for item in checks:
        print(f"- {item}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
