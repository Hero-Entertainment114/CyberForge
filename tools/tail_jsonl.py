#!/usr/bin/env python3
"""Continuous JSONL telemetry shipper with a local SQLite checkpoint.

The sender commits its byte offset only after the control plane acknowledges a
batch. A crash between acknowledgement and checkpoint commit causes safe replay;
CyberForge de-duplicates by (source, source_event_id). The shipper never logs
record content or credentials and never follows redirects.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import signal
import sqlite3
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SOURCES = ("wazuh", "suricata", "zeek", "falco", "osquery")
MAX_LINE_BYTES = 1024 * 1024
MAX_READ_BYTES = 8 * 1024 * 1024
MAX_BATCH = 50


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_server(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.rstrip("/"))
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("server must be a plain HTTPS origin; HTTP is allowed only for loopback")
    host = parsed.hostname.lower()
    local = host in {"localhost", "127.0.0.1", "::1"}
    if not local and parsed.scheme != "https":
        raise ValueError("remote CyberForge servers require HTTPS")
    if parsed.path not in {"", "/"}:
        raise ValueError("custom server paths are not accepted")
    return f"{parsed.scheme}://{parsed.netloc}"


def load_token(token_file: str | None, token_env: str) -> str:
    if token_file:
        path = Path(token_file).expanduser()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise ValueError("token file must be a regular non-symlink file") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("token file must be a regular non-symlink file")
            if stat.S_IMODE(st.st_mode) & 0o077:
                raise ValueError("token file must have permissions 0600 or stricter")
            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                fd = -1
                token = handle.read(1025).strip()
            if len(token) > 256:
                raise ValueError("a valid sensor token is required")
        finally:
            if fd >= 0:
                os.close(fd)
    else:
        token = os.getenv(token_env, "").strip()
    if not token or len(token) > 256 or "\n" in token or "\r" in token:
        raise ValueError("a valid sensor token is required")
    return token


def send_batch(server: str, source: str, token: str, records: list[dict[str, Any]], timeout: float = 10.0) -> dict[str, Any]:
    body = json.dumps({"events": records}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(server + "/api/v204/security/ingest/" + source, data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json",
                 "User-Agent": "CyberForge-Continuous-Telemetry/2.1.0"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=timeout) as response:
            if response.status != 202:
                raise RuntimeError("unexpected ingestion HTTP status")
            result = json.loads(response.read(256 * 1024).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        code = "request_failed"
        try:
            error = json.loads(exc.read(8192).decode("utf-8"))
            code = str(error.get("error", {}).get("code", code))[:80]
        except Exception:
            pass
        raise RuntimeError(f"CyberForge rejected telemetry (HTTP {exc.code}, {code})") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("unable to connect to the CyberForge server") from exc
    if not isinstance(result, dict) or not result.get("ok") or not isinstance(result.get("result"), dict):
        raise RuntimeError("CyberForge returned an invalid ingestion response")
    return result["result"]


class InstanceLock:
    def __init__(self, path: Path):
        self.path = path
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        if self.path.is_symlink():
            raise ValueError("state lock cannot be a symlink")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        self.handle = os.fdopen(fd, "r+")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.handle.close()
            raise RuntimeError("another telemetry shipper is using this checkpoint") from exc
        os.fchmod(self.handle.fileno(), 0o600)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.handle:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            finally:
                self.handle.close()


class CheckpointDB:
    def __init__(self, path: Path):
        self.path = path.expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        if self.path.is_symlink():
            raise ValueError("checkpoint database cannot be a symlink")
        self.con = sqlite3.connect(self.path, timeout=10)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=FULL")
        self.con.execute("""CREATE TABLE IF NOT EXISTS checkpoints(
            input_path TEXT PRIMARY KEY, device INTEGER NOT NULL, inode INTEGER NOT NULL,
            offset INTEGER NOT NULL, updated_at TEXT NOT NULL)""")
        self.con.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get(self, key: str):
        row = self.con.execute("SELECT device,inode,offset FROM checkpoints WHERE input_path=?", (key,)).fetchone()
        return (int(row[0]), int(row[1]), int(row[2])) if row else None

    def save(self, key: str, device: int, inode: int, offset: int):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.con.execute("""INSERT INTO checkpoints(input_path,device,inode,offset,updated_at) VALUES(?,?,?,?,?)
            ON CONFLICT(input_path) DO UPDATE SET device=excluded.device,inode=excluded.inode,
            offset=excluded.offset,updated_at=excluded.updated_at""", (key, device, inode, max(0, offset), now))
        self.con.commit()

    def close(self):
        self.con.close()


def instance_lock_path(state_path: Path, input_path: Path) -> Path:
    """Use one lock per input file so independent sensors can share a checkpoint DB."""
    canonical = str(input_path.expanduser().absolute()).encode("utf-8", errors="surrogateescape")
    digest = hashlib.sha256(canonical).hexdigest()[:16]
    return state_path.with_suffix(state_path.suffix + f".{digest}.lock")


def _find_rotated(path: Path, device: int, inode: int) -> Path | None:
    # Common rename-based rotations: file.log.1, file.log.2026-11-09, etc.
    for candidate in sorted(path.parent.glob(path.name + ".*"))[:100]:
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            st = candidate.stat()
            if st.st_dev == device and st.st_ino == inode:
                return candidate
        except OSError:
            continue
    return None


def _open_regular_file(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("input must be a regular non-symlink file") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("input must be a regular non-symlink file")
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise


class TailRunner:
    def __init__(self, path: Path, source: str, state: CheckpointDB, server: str, token: str,
                 batch_size: int = 25, start_at_end: bool = True, timeout: float = 10.0,
                 sender: Callable[..., dict[str, Any]] | None = None):
        if source not in SOURCES:
            raise ValueError("continuous tail supports Wazuh, Suricata, Zeek, Falco and osquery JSONL; Trivy reports use batch ingestion")
        self.path = path.expanduser()
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("input must be a regular non-symlink file")
        self.path = self.path.absolute()
        self.state = state
        self.source = source
        self.server = server
        self.token = token
        self.batch_size = max(1, min(MAX_BATCH, int(batch_size)))
        self.timeout = max(1.0, min(60.0, float(timeout)))
        self.sender = sender or send_batch
        self.key = str(self.path)
        saved = state.get(self.key)
        current = self.path.stat()
        if saved is None:
            self.active_path = self.path
            self.device, self.inode = current.st_dev, current.st_ino
            self.offset = 0 if not start_at_end else current.st_size
            state.save(self.key, self.device, self.inode, self.offset)
        else:
            self.device, self.inode, self.offset = saved
            if (current.st_dev, current.st_ino) != (self.device, self.inode):
                rotated = _find_rotated(self.path, self.device, self.inode)
                if not rotated:
                    raise RuntimeError("checkpointed log inode is no longer available; preserve the rotated file or reset the checkpoint deliberately")
                self.active_path = rotated
            else:
                self.active_path = self.path
        self.handle = _open_regular_file(self.active_path)
        if self.handle.seek(0, os.SEEK_END) < self.offset:
            # copytruncate: the same inode is shorter than our offset.
            self.offset = 0
            state.save(self.key, self.device, self.inode, self.offset)
        self.handle.seek(self.offset)
        self.stop = False
        self.last_stats = {"sent": 0, "accepted": 0, "duplicates": 0, "invalid_lines": 0, "partial_lines": 0}

    def close(self):
        try:
            self.handle.close()
        except Exception:
            pass

    def _checkpoint(self, offset: int):
        self.offset = offset
        self.state.save(self.key, self.device, self.inode, self.offset)

    def _switch_to_current(self):
        current = self.path.stat()
        if (current.st_dev, current.st_ino) == (self.device, self.inode):
            return False
        self.handle.close()
        self.active_path = self.path
        self.device, self.inode = current.st_dev, current.st_ino
        self.offset = 0
        self.handle = _open_regular_file(self.active_path)
        self._checkpoint(0)
        return True

    def poll_once(self) -> dict[str, int]:
        stats = {"sent": 0, "accepted": 0, "duplicates": 0, "invalid_lines": 0, "partial_lines": 0}
        # If copytruncate happens between polls, reset checkpoint safely. Server
        # event IDs still make already-sent lines idempotent.
        try:
            current_fd_stat = os.fstat(self.handle.fileno())
            if current_fd_stat.st_size < self.offset:
                self._checkpoint(0)
                self.handle.seek(0)
        except OSError:
            pass
        self.handle.seek(self.offset)
        cursor = self.offset
        batch: list[dict[str, Any]] = []
        batch_end = cursor
        at_eof = False
        while True:
            line_start = self.handle.tell()
            line = self.handle.readline(MAX_LINE_BYTES + 2)
            if not line:
                at_eof = True
                break
            if not line.endswith(b"\n"):
                # If this is an oversized line, drain to newline without keeping
                # unbounded data. A normal partial write is simply retried later.
                if len(line) > MAX_LINE_BYTES + 1:
                    while line and not line.endswith(b"\n"):
                        line = self.handle.readline(MAX_LINE_BYTES + 2)
                    if line.endswith(b"\n"):
                        cursor = self.handle.tell()
                        stats["invalid_lines"] += 1
                        batch_end = cursor
                        continue
                self.handle.seek(line_start)
                stats["partial_lines"] += 1
                break
            cursor = self.handle.tell()
            if len(line) > MAX_LINE_BYTES + 1:
                stats["invalid_lines"] += 1
                batch_end = cursor
                continue
            try:
                text = line.decode("utf-8", errors="strict").strip()
                if not text:
                    batch_end = cursor
                    continue
                obj = json.loads(text)
                if not isinstance(obj, dict):
                    raise ValueError("not_object")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                stats["invalid_lines"] += 1
                batch_end = cursor
                continue
            batch.append(obj)
            batch_end = cursor
            if len(batch) >= self.batch_size:
                result = self.sender(self.server, self.source, self.token, batch, self.timeout)
                stats["sent"] += len(batch)
                stats["accepted"] += int(result.get("accepted", 0))
                stats["duplicates"] += int(result.get("duplicates", 0))
                batch.clear()
                self._checkpoint(batch_end)
        if batch:
            result = self.sender(self.server, self.source, self.token, batch, self.timeout)
            stats["sent"] += len(batch)
            stats["accepted"] += int(result.get("accepted", 0))
            stats["duplicates"] += int(result.get("duplicates", 0))
            self._checkpoint(batch_end)
        elif batch_end > self.offset:
            # Includes blank/malformed lines. Bad lines are counted, never logged
            # with content, and skipped so one damaged record cannot stall a sensor.
            self._checkpoint(batch_end)
        # Rename rotation: drain the old open descriptor, then start the new path.
        if at_eof:
            try:
                current = self.path.stat()
                if (current.st_dev, current.st_ino) != (self.device, self.inode):
                    self._switch_to_current()
            except FileNotFoundError:
                pass
        self.last_stats = stats
        return stats

    def run(self, poll_interval: float = 1.0):
        poll_interval = max(0.2, min(30.0, float(poll_interval)))
        while not self.stop:
            try:
                stats = self.poll_once()
                if stats["sent"] or stats["invalid_lines"]:
                    print(json.dumps(stats), flush=True)
            except Exception as exc:
                # Do not print telemetry or credentials, only a bounded error.
                print(f"telemetry-tail: {str(exc)[:240]}", file=sys.stderr, flush=True)
            time.sleep(poll_interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Continuously tail a security JSONL log with durable checkpoints.")
    parser.add_argument("--source", choices=SOURCES, required=True)
    parser.add_argument("--server", required=True, help="CyberForge server origin; remote server requires HTTPS")
    parser.add_argument("--input", required=True, help="JSONL file to follow")
    parser.add_argument("--token-env", default="CF_SECURITY_INGEST_TOKEN")
    parser.add_argument("--token-file", help="mode-0600 sensor token file")
    parser.add_argument("--state-file", default="~/.local/state/cyberforge-telemetry/checkpoints.sqlite3")
    parser.add_argument("--batch-size", type=int, default=25)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--from-beginning", action="store_true", help="ingest existing content on first start; default starts at EOF")
    parser.add_argument("--once", action="store_true", help="process one available file segment and exit")
    args = parser.parse_args(argv)
    if not 1 <= args.batch_size <= MAX_BATCH:
        parser.error(f"--batch-size must be between 1 and {MAX_BATCH}")
    try:
        server = validate_server(args.server)
        token = load_token(args.token_file, args.token_env)
        state_path = Path(args.state_file).expanduser()
        lock_path = instance_lock_path(state_path, Path(args.input))
        with InstanceLock(lock_path):
            state = CheckpointDB(state_path)
            runner = None
            try:
                runner = TailRunner(Path(args.input), args.source, state, server, token, args.batch_size,
                                    start_at_end=not args.from_beginning, timeout=args.timeout)
                if args.once:
                    print(json.dumps(runner.poll_once(), indent=2))
                else:
                    def stop_handler(_signum, _frame):
                        if runner:
                            runner.stop = True
                    signal.signal(signal.SIGTERM, stop_handler)
                    signal.signal(signal.SIGINT, stop_handler)
                    print(json.dumps({"source": args.source, "input": str(Path(args.input).absolute()),
                                      "checkpoint": str(state_path), "status": "watching"}), flush=True)
                    runner.run(args.poll_interval)
                return 0
            finally:
                if runner:
                    runner.close()
                state.close()
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"telemetry-tail: {str(exc)[:240]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
