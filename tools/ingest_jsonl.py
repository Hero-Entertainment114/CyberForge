#!/usr/bin/env python3
"""Ship defensive JSON/JSONL telemetry to CyberForge Server Edition.

Supports Wazuh alerts, Suricata EVE, Zeek JSON logs, Falco JSON output,
Trivy JSON reports, and osquery result logs. The shipper never follows redirects
or prints tokens/payloads. It requires HTTPS for remote servers.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterator, Any

SOURCES = ("wazuh", "suricata", "zeek", "falco", "trivy", "osquery")
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_BATCH = 50


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_token(args) -> str:
    if args.token_file:
        path = Path(args.token_file).expanduser()
        st = path.stat()
        if os.name == "posix" and stat.S_IMODE(st.st_mode) & 0o077:
            raise ValueError("Token file permissions must be 0600 or stricter.")
        token = path.read_text(encoding="utf-8").strip()
    else:
        token = os.getenv(args.token_env, "").strip()
    if not token or len(token) > 256 or "\n" in token:
        raise ValueError("A valid sensor token is required via --token-file or the selected environment variable.")
    return token


def validate_server(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.rstrip("/"))
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Server must be a plain HTTPS URL (HTTP is permitted only for loopback).")
    host = parsed.hostname.lower()
    local = host in {"localhost", "127.0.0.1", "::1"}
    if not local and parsed.scheme != "https":
        raise ValueError("Remote CyberForge servers require HTTPS.")
    if parsed.path not in {"", "/"}:
        raise ValueError("Use the server origin only; custom URL paths are not accepted.")
    return f"{parsed.scheme}://{parsed.netloc}"


def _trivy_findings(doc: dict[str, Any]) -> Iterator[dict[str, Any]]:
    created = doc.get("CreatedAt")
    for result in (doc.get("Results") or [])[:200]:
        if not isinstance(result, dict):
            continue
        target = result.get("Target", "unknown-target")
        for field in ("Vulnerabilities", "Misconfigurations", "Secrets", "Licenses"):
            values = result.get(field) or []
            if not isinstance(values, list):
                continue
            for finding in values[:300]:
                if isinstance(finding, dict):
                    # Keep only labels needed by the normalizer. In particular, never
                    # ship Trivy secret Match/Code/line snippets to the control plane.
                    allowed = {
                        "Vulnerabilities": ("VulnerabilityID", "PkgName", "Severity", "Title", "InstalledVersion", "FixedVersion", "PrimaryURL", "PkgPath"),
                        "Misconfigurations": ("ID", "AVDID", "Severity", "Title", "Message", "Resolution", "PrimaryURL"),
                        "Secrets": ("RuleID", "Title", "Severity", "Category"),
                        "Licenses": ("Name", "Severity", "Category", "PkgName"),
                    }[field]
                    safe_finding = {key: finding[key] for key in allowed if key in finding and isinstance(finding[key], (str, int, float, bool))}
                    if not safe_finding:
                        continue
                    # Build a tiny one-finding envelope; never transmit report-wide metadata.
                    yield {"CreatedAt": created, "Results": [{"Target": target, field: [safe_finding]}]}


def iter_records(path: Path, source: str, input_format: str) -> Iterator[dict[str, Any]]:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"Input file exceeds {MAX_FILE_BYTES} bytes.")
    if input_format == "trivy" or (input_format == "auto" and source == "trivy"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise ValueError("Trivy input must be a JSON report object.")
        yield from _trivy_findings(doc)
        return
    if input_format == "json":
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, list):
            for item in doc:
                if isinstance(item, dict):
                    yield item
        elif isinstance(doc, dict):
            yield doc
        else:
            raise ValueError("JSON input must be an object or array of objects.")
        return
    # JSONL: one complete JSON object per line. Blank lines are ignored.
    with path.open("r", encoding="utf-8", errors="strict") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_no}.") from exc
            if isinstance(obj, dict):
                yield obj
            else:
                raise ValueError(f"Line {line_no} is not a JSON object.")


def send_batch(server: str, source: str, token: str, batch: list[dict[str, Any]], timeout: float) -> dict[str, Any]:
    url = server + "/api/v204/security/ingest/" + source
    body = json.dumps({"events": batch}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": "CyberForge-Security-Ingest/2.1.0",
    })
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            if response.status != 202:
                raise RuntimeError(f"Unexpected HTTP status {response.status}.")
            result = json.loads(response.read(256 * 1024).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Response body contains only the normalized error envelope; cap it.
        try:
            error = json.loads(exc.read(8192).decode("utf-8"))
            code = error.get("error", {}).get("code", "request_failed")
        except Exception:
            code = "request_failed"
        raise RuntimeError(f"CyberForge rejected the batch (HTTP {exc.code}, {code}).") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("Unable to connect to the CyberForge server.") from exc
    if not isinstance(result, dict) or not result.get("ok"):
        raise RuntimeError("CyberForge returned an invalid ingestion response.")
    return result.get("result", {})


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest JSONL security telemetry into CyberForge.")
    parser.add_argument("--source", choices=SOURCES, required=True)
    parser.add_argument("--server", required=True, help="CyberForge server origin; remote servers must use HTTPS")
    parser.add_argument("--input", required=True, help="Input JSONL/JSON file")
    parser.add_argument("--format", choices=("auto", "jsonl", "json", "trivy"), default="auto")
    parser.add_argument("--token-env", default="CF_SECURITY_INGEST_TOKEN")
    parser.add_argument("--token-file")
    parser.add_argument("--batch-size", type=int, default=25)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.batch_size <= MAX_BATCH:
        parser.error(f"--batch-size must be 1..{MAX_BATCH}")
    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be 1..60 seconds")
    try:
        server = validate_server(args.server)
        path = Path(args.input).expanduser()
        token = "" if args.dry_run else load_token(args)
        total = accepted = duplicates = ignored = batches = 0
        batch: list[dict[str, Any]] = []
        for record in iter_records(path, args.source, args.format):
            total += 1
            batch.append(record)
            if len(batch) >= args.batch_size:
                if args.dry_run:
                    print(f"validated batch {batches + 1}: {len(batch)} records")
                else:
                    result = send_batch(server, args.source, token, batch, args.timeout)
                    accepted += int(result.get("accepted", 0)); duplicates += int(result.get("duplicates", 0)); ignored += int(result.get("ignored", 0))
                batches += 1; batch.clear()
        if batch:
            if args.dry_run:
                print(f"validated batch {batches + 1}: {len(batch)} records")
            else:
                result = send_batch(server, args.source, token, batch, args.timeout)
                accepted += int(result.get("accepted", 0)); duplicates += int(result.get("duplicates", 0)); ignored += int(result.get("ignored", 0))
            batches += 1
        print(json.dumps({"source": args.source, "records": total, "batches": batches,
                          "accepted": accepted if not args.dry_run else None,
                          "duplicates": duplicates if not args.dry_run else None,
                          "ignored": ignored if not args.dry_run else None,
                          "dry_run": bool(args.dry_run)}, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"ingest_jsonl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
