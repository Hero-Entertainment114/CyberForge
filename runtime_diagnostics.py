"""Bounded compatibility, performance and recovery diagnostics for CyberForge.

All active probes are local and use temporary directories. No engine is launched,
no source file is executed, and no production database row is written by a probe.
"""
from __future__ import annotations

import hashlib
import html.parser
import importlib.util
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

DIAGNOSTICS_SCHEMA = "cyberforge.diagnostics.v1"
MIN_PYTHON = (3, 10)
MIN_SQLITE = (3, 24, 0)

RUNTIME_GROUPS: dict[str, list[str]] = {
    "python": ["python", "python3", "py"],
    "javascript_typescript": ["node", "npm", "pnpm", "yarn", "bun", "deno", "tsc"],
    "java_kotlin": ["java", "javac", "kotlin", "kotlinc", "gradle", "mvn"],
    "dotnet": ["dotnet"],
    "systems": ["gcc", "g++", "clang", "clang++", "rustc", "cargo", "go"],
    "scripting": ["php", "ruby", "perl", "lua", "bash", "pwsh", "powershell"],
    "data_and_build": ["git", "make", "cmake", "terraform", "docker-compose", "podman-compose"],
}
LSP_GROUPS: dict[str, list[str]] = {
    "python": ["pyright-langserver", "basedpyright-langserver", "pylsp", "jedi-language-server"],
    "web": ["typescript-language-server", "vscode-html-language-server", "vscode-css-language-server", "eslint"],
    "systems": ["rust-analyzer", "gopls", "clangd", "jdtls", "omnisharp", "lua-language-server"],
    "other": ["solargraph", "intelephense", "bash-language-server", "yaml-language-server", "taplo"],
}
SCANNER_GROUPS: dict[str, list[str]] = {
    "sast_and_secrets": ["bandit", "semgrep", "gitleaks", "ruff", "pylint", "flake8"],
    "supply_chain_and_iac": ["trivy", "grype", "syft", "checkov", "snyk", "osv-scanner"],
    "malware_and_forensics": ["clamscan", "yara", "yarac", "capa", "floss", "olevba", "vol", "volatility3"],
}
SANDBOX_GROUPS: dict[str, list[str]] = {
    "containers": ["docker", "podman"],
    "linux_isolation": ["firejail", "bwrap", "unshare", "systemd-run"],
    "virtual_machines": ["VBoxManage", "virsh", "vmrun", "qemu-system-x86_64", "qemu-system-aarch64"],
}
VERSION_COMMANDS: dict[str, list[str]] = {
    "node": ["--version"], "npm": ["--version"], "bun": ["--version"], "deno": ["--version"],
    "python": ["--version"], "python3": ["--version"], "git": ["--version"],
    "docker": ["--version"], "podman": ["--version"], "go": ["version"],
    "rustc": ["--version"], "cargo": ["--version"], "java": ["-version"],
    "javac": ["-version"], "dotnet": ["--version"], "gcc": ["--version"],
    "clang": ["--version"], "firejail": ["--version"], "VBoxManage": ["--version"],
}


def _version_probe(name: str, executable: str) -> str | None:
    args = VERSION_COMMANDS.get(name)
    if not args:
        return None
    try:
        done = subprocess.run([executable, *args], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=1.25, check=False, shell=False,
                              env={**os.environ, "NO_COLOR": "1", "CI": "1"})
        raw = done.stdout[:4096].decode("utf-8", "replace").strip().splitlines()
        return raw[0][:180] if raw else (f"exit {done.returncode}" if done.returncode else "version unavailable")
    except (OSError, subprocess.TimeoutExpired):
        return "version probe timed out or was unavailable"


def _inventory(groups: dict[str, list[str]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for group, names in groups.items():
        rows = []
        for name in names:
            path = shutil.which(name)
            rows.append({"name": name, "available": bool(path),
                         "path": path, "version": _version_probe(name, path) if path else None})
        result[group] = {"items": rows, "available": sum(x["available"] for x in rows), "total": len(rows)}
    return result


def _optional_modules() -> list[dict[str, Any]]:
    modules = {
        "psutil": ("psutil", "Process metrics / resource profiling"),
        "cryptography": ("cryptography", "Encrypted evidence vault"),
        "PIL": ("Pillow", "Image and QR support"), "webview": ("pywebview", "Native desktop shell"),
        "yaml": ("PyYAML", "YAML parsing"), "yara": ("yara-python", "In-process YARA scanning"),
        "magic": ("python-magic", "File type detection"), "evtx": ("python-evtx", "Windows EVTX parsing"),
        "Registry": ("python-registry", "Windows Registry parsing"),
        "requests": ("requests", "Optional HTTP integration"), "bs4": ("beautifulsoup4", "HTML parsing helpers"),
    }
    rows = []
    for name, (distribution, purpose) in modules.items():
        try:
            found = importlib.util.find_spec(name) is not None
        except (ImportError, ValueError, AttributeError):
            found = False
        try:
            from importlib.metadata import version as package_version
            package_ver = package_version(distribution) if found else None
        except Exception:
            package_ver = "installed; version metadata unavailable" if found else None
        rows.append({"name": name, "distribution": distribution, "available": found,
                     "version": package_ver, "purpose": purpose,
                     "required": name == "cryptography",
                     "status": "available" if found else ("required_missing" if name == "cryptography" else "optional_missing")})
    return rows


def _platform_matrix() -> list[dict[str, Any]]:
    system = platform.system()
    machine = platform.machine().lower()
    known_arch = machine in {"x86_64", "amd64", "aarch64", "arm64", "i386", "i686"}
    supported_os = system in {"Windows", "Linux", "Darwin"}
    return [
        {"component": "Core Python application", "status": "compatible" if supported_os else "review",
         "reason": f"OS={system}; architecture={platform.machine()}. Native builds are defined for Windows, macOS and Linux."},
        {"component": "CPU architecture", "status": "compatible" if known_arch else "review",
         "reason": "Architecture is recognized by the compatibility profile." if known_arch else "Unrecognized architecture; verify Python wheels and native engine availability."},
        {"component": "Firejail / bubblewrap", "status": "compatible" if system == "Linux" else "unsupported",
         "reason": "Linux namespace/seccomp facilities are required."},
        {"component": "AnonSurf / BlackArch package groups", "status": "compatible" if system == "Linux" else "unsupported",
         "reason": "Requires a compatible Linux distribution; BlackArch group queries additionally require pacman and configured repositories."},
        {"component": "Docker / Podman", "status": "review", "reason": "Cross-platform runtime; a detected CLI does not prove daemon/socket access or that required images exist."},
        {"component": "VirtualBox / libvirt / VMware", "status": "review", "reason": "Hypervisor CLI detection is not a guest-isolation or VM-configuration audit."},
    ]


def compatibility_report(root: Path, data_dir: Path, db_path: Path, ui_path: Path,
                          app_version: str, engine_inventory: list[dict[str, Any]] | None = None,
                          scanner_inventory: list[dict[str, Any]] | None = None,
                          language_count: int | None = None,
                          sandbox_runtime: dict[str, Any] | None = None) -> dict[str, Any]:
    py_version = tuple(sys.version_info[:3])
    sqlite_version = tuple(sqlite3.sqlite_version_info)
    python_ok = py_version >= MIN_PYTHON
    sqlite_ok = sqlite_version >= MIN_SQLITE
    memory_total = memory_available = None
    try:
        if sys.platform.startswith("linux"):
            for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
                if line.startswith("MemTotal:"):
                    memory_total = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    memory_available = int(line.split()[1]) * 1024
        elif hasattr(os, "sysconf"):
            memory_total = int(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
            memory_available = int(os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError, AttributeError):
        pass
    runtimes = _inventory(RUNTIME_GROUPS)
    lsps = _inventory(LSP_GROUPS)
    scanners = _inventory(SCANNER_GROUPS)
    sandboxes = _inventory(SANDBOX_GROUPS)
    version_compatibility = [
        {"component": "Python runtime", "detected": platform.python_version(), "policy": ">= 3.10",
         "status": "compatible" if python_ok else "incompatible", "basis": "CyberForge source runtime baseline"},
        {"component": "SQLite library", "detected": sqlite3.sqlite_version, "policy": ">= 3.24.0",
         "status": "compatible" if sqlite_ok else "incompatible", "basis": "SQLite features used by the application"},
    ]
    version_inventory = []
    for category, groups in (("runtime", runtimes), ("lsp", lsps), ("scanner", scanners), ("sandbox", sandboxes)):
        for group_name, group in groups.items():
            for tool in group.get("items", []):
                if tool.get("available"):
                    version_inventory.append({"category": category, "group": group_name,
                                              "name": tool.get("name"), "version": tool.get("version") or "unknown"})
    for module in _optional_modules():
        if module.get("available"):
            version_inventory.append({"category": "python_library", "name": module["name"],
                                      "distribution": module["distribution"], "version": module.get("version") or "unknown"})
    engine_version_checks = []
    for engine in (engine_inventory or []):
        active = engine.get("active_version")
        allowed = engine.get("available_versions") or []
        if active:
            engine_version_checks.append({"component": str(engine.get("id", "engine")), "detected": str(active),
                                          "policy": "must be present in the bundled engine catalog",
                                          "status": "compatible" if active in allowed else "incompatible"})
    version_compatibility.extend(engine_version_checks)
    checks = [
        {"component": "Python", "status": "compatible" if python_ok else "incompatible",
         "detected": platform.python_version(), "required": ">= 3.10", "executable": sys.executable,
         "implementation": platform.python_implementation(), "pointer_bits": 64 if sys.maxsize > 2**32 else 32},
        {"component": "SQLite", "status": "compatible" if sqlite_ok else "incompatible",
         "detected": sqlite3.sqlite_version, "required": ">= 3.24.0", "threadsafety": sqlite3.threadsafety},
        {"component": "OS", "status": "compatible" if platform.system() in {"Windows", "Linux", "Darwin"} else "review",
         "detected": platform.platform()},
        {"component": "Application data path", "status": "compatible" if data_dir.exists() and os.access(data_dir, os.R_OK | os.W_OK) else "review",
         "path_exists": data_dir.exists(), "read_write_access": os.access(data_dir, os.R_OK | os.W_OK)},
        {"component": "SQLite database", "status": "compatible" if db_path.is_file() else "not_initialized",
         "exists": db_path.is_file(), "size_bytes": db_path.stat().st_size if db_path.is_file() else 0},
        {"component": "Frontend bundle", "status": "compatible" if ui_path.is_file() else "incompatible",
         "exists": ui_path.is_file(), "size_bytes": ui_path.stat().st_size if ui_path.is_file() else 0},
    ]
    return {
        "schema": DIAGNOSTICS_SCHEMA, "version": app_version, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {"os": platform.system(), "os_release": platform.release(), "platform": platform.platform(),
                 "architecture": platform.machine(), "processor": platform.processor() or "unknown",
                 "logical_cpus": os.cpu_count(), "memory_total_bytes": memory_total,
                 "memory_available_bytes": memory_available},
        "checks": checks, "platform_matrix": _platform_matrix(),
        "runtime_groups": runtimes, "lsp_groups": lsps, "scanner_groups": scanners,
        "sandbox_groups": sandboxes, "optional_modules": _optional_modules(),
        "version_compatibility": version_compatibility, "version_inventory": version_inventory,
        "sandbox_runtime_probe": sandbox_runtime or {"engines": [], "status": "not_probed"},
        "managed_engines": [{"id": x.get("id"), "name": x.get("name"), "ready": bool(x.get("ready")),
                             "managed": bool(x.get("managed")), "active_version": x.get("active_version"),
                             "system_path_detected": bool(x.get("system_path"))}
                            for x in (engine_inventory or [])],
        "scanner_adapters": [{"id": x.get("id"), "label": x.get("label"),
                               "available": bool(x.get("available")), "path_detected": bool(x.get("path"))}
                              for x in (scanner_inventory or [])],
        "managed_engine_ids": sorted({str(x.get("id")) for x in (engine_inventory or []) if x.get("managed") or x.get("ready")}),
        "registered_scanner_ids": sorted({str(x.get("id")) for x in (scanner_inventory or [])}),
        "language_profile_count": language_count,
        "summary": {"compatible": sum(x["status"] == "compatible" for x in checks),
                    "incompatible": sum(x["status"] == "incompatible" for x in checks),
                    "review": sum(x["status"] in {"review", "not_initialized"} for x in checks)},
        "notice": "Discovery is read-only. A detected executable does not prove permissions, daemon health, compatible plugin ABI, configured signatures, or successful end-to-end operation.",
    }


class _FrontendCounter(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements = 0
        self.ids: list[str] = []
        self.inline_handlers = 0
        self.inline_script_bytes = 0
        self.script_count = 0
        self.external_scripts: list[str] = []
        self._inside_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements += 1
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"] or "")
        self.inline_handlers += sum(1 for key, _ in attrs if key.lower().startswith("on"))
        if tag.lower() == "script":
            self.script_count += 1
            self._inside_script = True
            if values.get("src"):
                self.external_scripts.append(values["src"] or "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._inside_script = False

    def handle_data(self, data: str) -> None:
        if self._inside_script:
            self.inline_script_bytes += len(data.encode("utf-8", "replace"))


def frontend_report(ui_path: Path) -> dict[str, Any]:
    if not ui_path.is_file():
        return {"status": "missing", "error": "Frontend file is missing."}
    raw = ui_path.read_bytes()
    text = raw.decode("utf-8", "replace")
    parser = _FrontendCounter()
    parser.feed(text)
    parser.close()
    duplicates = sorted({item for item in parser.ids if parser.ids.count(item) > 1})
    css_bytes = sum(len(m.group(1).encode("utf-8")) for m in __import__("re").finditer(r"<style[^>]*>(.*?)</style\s*>", text, __import__("re").I | __import__("re").S))
    return {
        "status": "warning" if len(raw) > 512 * 1024 or parser.inline_script_bytes > 320 * 1024 or duplicates else "ok",
        "html_bytes": len(raw), "element_count": parser.elements, "unique_id_count": len(set(parser.ids)),
        "duplicate_ids": duplicates[:50], "inline_event_handlers": parser.inline_handlers,
        "script_count": parser.script_count, "external_scripts": parser.external_scripts,
        "inline_script_bytes": parser.inline_script_bytes, "inline_style_bytes": css_bytes,
        "budgets": {"html_warning_bytes": 512 * 1024, "inline_script_warning_bytes": 320 * 1024},
        "notice": "Static bundle analysis only. Browser paint, layout, interaction latency and real-device memory require browser automation on the target host.",
    }


def _sqlite_report(db_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"exists": db_path.is_file(), "path_name": db_path.name}
    if not db_path.is_file():
        return result
    result["db_bytes"] = db_path.stat().st_size
    result["wal_bytes"] = Path(str(db_path) + "-wal").stat().st_size if Path(str(db_path) + "-wal").exists() else 0
    result["shm_bytes"] = Path(str(db_path) + "-shm").stat().st_size if Path(str(db_path) + "-shm").exists() else 0
    try:
        uri = "file:" + urllib.parse.quote(str(db_path.resolve())) + "?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=2)
        try:
            # Match the application's bounded per-connection settings so this
            # read-only profile reports the operational configuration, not SQLite defaults.
            con.execute("PRAGMA cache_size=-2048")
            con.execute("PRAGMA temp_store=MEMORY")
            con.execute("PRAGMA wal_autocheckpoint=500")
            pragmas = {}
            for key in ("journal_mode", "synchronous", "page_size", "page_count", "freelist_count", "cache_size", "mmap_size", "wal_autocheckpoint", "temp_store"):
                try:
                    row = con.execute(f"PRAGMA {key}").fetchone()
                    pragmas[key] = row[0] if row else None
                except sqlite3.DatabaseError:
                    pragmas[key] = None
            result["pragmas"] = pragmas
            result["table_count"] = con.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchone()[0]
            result["index_count"] = con.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'").fetchone()[0]
            result["quick_check"] = con.execute("PRAGMA quick_check").fetchone()[0]
            result["foreign_key_violations"] = len(con.execute("PRAGMA foreign_key_check").fetchmany(100))
            plan_queries = {
                "cases_priority_updated": ("SELECT id FROM cases ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'investigating' THEN 1 WHEN 'contained' THEN 2 ELSE 3 END, updated_at DESC LIMIT 100", ()),
                "assets_by_case_updated": ("SELECT id FROM assets WHERE case_id=? ORDER BY updated_at DESC", ("__probe__",)),
                "findings_by_case_severity": ("SELECT id FROM findings WHERE case_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, updated_at DESC", ("__probe__",)),
                "workflows_by_case_created": ("SELECT id FROM workflow_runs WHERE case_id=? ORDER BY created_at DESC LIMIT 100", ("__probe__",)),
            }
            plans = {}
            for label, (sql, params) in plan_queries.items():
                plans[label] = [str(row[3]) for row in con.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()]
            result["query_plans"] = plans
            result["indexed_query_paths"] = {key: any("USING INDEX" in line or "USING COVERING INDEX" in line for line in rows)
                                              for key, rows in plans.items()}
        finally:
            con.close()
        result["status"] = "ok" if result.get("quick_check") == "ok" and result.get("foreign_key_violations") == 0 else "warning"
    except (OSError, sqlite3.DatabaseError) as exc:
        result.update({"status": "error", "error_type": type(exc).__name__})
    return result


def performance_report(db_path: Path, data_dir: Path, ui_path: Path,
                       runtime_snapshot: dict[str, Any], samples: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    sqlite_info = _sqlite_report(db_path)
    frontend = frontend_report(ui_path)
    try:
        disk = shutil.disk_usage(data_dir if data_dir.exists() else db_path.parent)
        disk_info = {"free_bytes": disk.free, "total_bytes": disk.total}
    except OSError:
        disk_info = {"free_bytes": None, "total_bytes": None}
    history = samples or []
    rss_values = [int(x["rss_bytes"]) for x in history if isinstance(x.get("rss_bytes"), int)]
    window_seconds = history[-1]["time"] - history[0]["time"] if len(history) >= 2 else 0
    memory_delta = rss_values[-1] - rss_values[0] if len(rss_values) >= 2 else None
    cpu_delta = (history[-1].get("cpu_time_seconds", 0) - history[0].get("cpu_time_seconds", 0)) if len(history) >= 2 else None
    possible_growth = bool(len(rss_values) >= 6 and window_seconds >= 60 and memory_delta is not None
                           and memory_delta > max(32 * 1024 * 1024, int(rss_values[0] * 0.15)))
    return {
        "schema": DIAGNOSTICS_SCHEMA, "captured_at": time.time(),
        "process": runtime_snapshot,
        "memory_trend": {"sample_count": len(history), "oldest_rss_bytes": rss_values[0] if rss_values else None,
                         "latest_rss_bytes": rss_values[-1] if rss_values else runtime_snapshot.get("memory_rss_bytes"),
                         "delta_bytes": memory_delta,
                         "window_seconds": round(window_seconds, 2),
                         "possible_growth": possible_growth,
                         "assessment": "possible_growth_retest_same_workload" if possible_growth else "insufficient_or_no_growth_signal",
                         "gc_tracked_objects_delta": (history[-1].get("gc_tracked_objects", 0) - history[0].get("gc_tracked_objects", 0)) if len(history) >= 2 else None,
                         "file_descriptor_delta": (history[-1].get("open_file_descriptors", 0) - history[0].get("open_file_descriptors", 0)) if len(history) >= 2 and history[-1].get("open_file_descriptors") is not None and history[0].get("open_file_descriptors") is not None else None,
                         "cpu_percent_over_window": round((cpu_delta / window_seconds) * 100, 1) if cpu_delta is not None and window_seconds > 0 else None,
                         "samples": history[-40:]},
        "sqlite": sqlite_info, "frontend": frontend, "disk": disk_info,
        "recommendations": [
            "SQLite read-only diagnostics do not rewrite or vacuum the production database.",
            "Run a verified online backup before any maintenance. WAL checkpoint is available as an explicit user action.",
            "A rising RSS trend is an observation, not proof of a leak; repeat the same workload and inspect a longer window.",
            "Use browser profiling on the target device for paint, scripting and layout measurements.",
        ],
    }


def sqlite_benchmark(iterations: int = 1200) -> dict[str, Any]:
    iterations = max(100, min(int(iterations), 5000))
    with tempfile.TemporaryDirectory(prefix="cyberforge-sqlbench-") as temp:
        path = Path(temp) / "benchmark.sqlite3"
        con = sqlite3.connect(path, timeout=5)
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
            con.execute("PRAGMA temp_store=MEMORY")
            con.execute("CREATE TABLE measurements (id INTEGER PRIMARY KEY, group_id INTEGER, payload TEXT NOT NULL)")
            con.execute("CREATE INDEX idx_measurements_group ON measurements(group_id)")
            start = time.perf_counter()
            with con:
                con.executemany("INSERT INTO measurements(group_id,payload) VALUES(?,?)",
                                ((i % 31, hashlib.sha256(str(i).encode()).hexdigest()) for i in range(iterations)))
            write_ms = (time.perf_counter() - start) * 1000
            start = time.perf_counter()
            rows = con.execute("SELECT COUNT(*), COUNT(DISTINCT group_id) FROM measurements WHERE group_id BETWEEN 5 AND 25").fetchone()
            read_ms = (time.perf_counter() - start) * 1000
            integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
            plan = [str(row[3]) for row in con.execute("EXPLAIN QUERY PLAN SELECT * FROM measurements WHERE group_id=?", (12,)).fetchall()]
        finally:
            con.close()
        return {"iterations": iterations, "write_ms": round(write_ms, 2), "read_ms": round(read_ms, 2),
                "rows_matched": int(rows[0]), "groups_matched": int(rows[1]), "integrity": integrity,
                "query_plan": plan, "used_index": any("idx_measurements_group" in item for item in plan),
                "database": "temporary benchmark database; production data was not touched"}


def concurrency_stress(workers: int = 8, tasks: int = 80) -> dict[str, Any]:
    workers = max(2, min(int(workers), 16))
    tasks = max(workers, min(int(tasks), 300))
    latencies: list[float] = []
    failures: list[str] = []
    sample_lock = threading.Lock()
    rss_before = _rss_bytes()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="cyberforge-stress-") as temp:
        db_path = Path(temp) / "stress.sqlite3"
        setup = sqlite3.connect(db_path, timeout=10)
        try:
            setup.execute("PRAGMA journal_mode=WAL")
            setup.execute("PRAGMA synchronous=NORMAL")
            setup.execute("CREATE TABLE jobs (id INTEGER PRIMARY KEY, digest TEXT NOT NULL, worker INTEGER NOT NULL)")
            setup.commit()
        finally:
            setup.close()

        def task(index: int) -> None:
            tick = time.perf_counter()
            digest = hashlib.sha256((f"cyberforge-stress-{index}".encode()) * 1024).hexdigest()
            con = sqlite3.connect(db_path, timeout=10)
            try:
                con.execute("INSERT INTO jobs(digest,worker) VALUES(?,?)", (digest, index % workers))
                con.commit()
            finally:
                con.close()
            with sample_lock:
                latencies.append((time.perf_counter() - tick) * 1000)

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="CFStress") as pool:
            futures = [pool.submit(task, i) for i in range(tasks)]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    failures.append(type(exc).__name__ + ": " + str(exc)[:160])
        elapsed = time.perf_counter() - started
        check = sqlite3.connect(db_path, timeout=5)
        try:
            integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
            completed = int(check.execute("SELECT COUNT(*) FROM jobs").fetchone()[0])
        finally:
            check.close()
    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered)-1, int(len(ordered)*0.95))] if ordered else None
    rss_after = _rss_bytes()
    return {"workers": workers, "requested_tasks": tasks, "completed_tasks": len(latencies),
            "database_rows": completed, "failures": failures[:20], "integrity": integrity,
            "elapsed_seconds": round(elapsed, 3), "tasks_per_second": round(len(latencies) / elapsed, 2) if elapsed else 0,
            "latency_ms": {"median": round(ordered[len(ordered)//2], 2) if ordered else None,
                           "p95": round(p95, 2) if p95 is not None else None,
                           "max": round(max(ordered), 2) if ordered else None},
            "rss_before_bytes": rss_before, "rss_after_bytes": rss_after,
            "rss_delta_bytes": rss_after-rss_before if rss_before is not None and rss_after is not None else None,
            "scope": "bounded local thread + SQLite WAL stress harness; does not generate external network traffic or write to the production database"}


def _rss_bytes() -> int | None:
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            pass
    try:
        import psutil  # type: ignore
        return int(psutil.Process(os.getpid()).memory_info().rss)
    except Exception:
        return None


def crash_recovery_probe() -> dict[str, Any]:
    """Hard-exit a child with an uncommitted WAL transaction, then verify recovery."""
    script = r'''import os, sqlite3, sys
p=sys.argv[1]
c=sqlite3.connect(p, timeout=5)
c.execute("PRAGMA journal_mode=WAL")
c.execute("PRAGMA synchronous=FULL")
c.execute("CREATE TABLE IF NOT EXISTS recovery_probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
c.execute("INSERT INTO recovery_probe(value) VALUES('committed-before-crash')")
c.commit()
c.execute("BEGIN IMMEDIATE")
c.execute("INSERT INTO recovery_probe(value) VALUES('must-rollback-after-crash')")
os._exit(23)
'''
    with tempfile.TemporaryDirectory(prefix="cyberforge-crash-probe-") as temp:
        db = Path(temp) / "crash.sqlite3"
        try:
            child = subprocess.run([sys.executable, "-c", script, str(db)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=8, check=False, shell=False)
            con = sqlite3.connect(db, timeout=5)
            try:
                integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
                values = [row[0] for row in con.execute("SELECT value FROM recovery_probe ORDER BY id")]
                journal = con.execute("PRAGMA journal_mode").fetchone()[0]
            finally:
                con.close()
            passed = child.returncode == 23 and integrity == "ok" and values == ["committed-before-crash"] and journal.lower() == "wal"
            return {"passed": passed, "child_exit_code": child.returncode, "integrity": integrity,
                    "recovered_committed_rows": len(values), "uncommitted_transaction_rolled_back": values == ["committed-before-crash"],
                    "journal_mode": journal, "scope": "isolated temporary SQLite WAL database; production DB and user files were not touched"}
        except (OSError, subprocess.TimeoutExpired, sqlite3.DatabaseError) as exc:
            return {"passed": False, "error_type": type(exc).__name__, "message": str(exc)[:200],
                    "scope": "isolated temporary SQLite WAL database"}



def gpu_inventory() -> dict[str, Any]:
    """Best-effort GPU inventory; does not initialize CUDA or load GPU libraries."""
    import re
    rows = []
    probes = (("nvidia-smi", ["--query-gpu=name,memory.total,memory.used,utilization.gpu", "--format=csv,noheader,nounits"]),
              ("rocm-smi", ["--showproductname", "--showmeminfo", "vram"]), ("rocminfo", []))
    for name, args in probes:
        executable = shutil.which(name)
        if not executable: continue
        try:
            done = subprocess.run([executable, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=1.5, check=False, shell=False,
                                  env={**os.environ, "NO_COLOR": "1"})
            output = done.stdout[:5000].decode("utf-8", "replace").strip()
            rows.append({"tool": name, "available": True, "exit_code": done.returncode,
                         "summary": re.sub(r"\s+", " ", output)[:900] or "No inventory output"})
        except (OSError, subprocess.TimeoutExpired):
            rows.append({"tool": name, "available": True, "status": "probe_timeout"})
    return {"detected_tools": rows, "status": "detected" if rows else "no_vendor_cli_detected",
            "note": "No GPU workload is run. CyberForge core UI/security workflows do not currently require GPU acceleration."}
