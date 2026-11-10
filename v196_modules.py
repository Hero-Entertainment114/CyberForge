"""v1.9.6 Dev Studio IDE services.

The terminal is an explicitly user-started local shell scoped initially to a
selected project directory. It is NOT a sandbox and commands may access the
host account's normal permissions.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any


MAX_TERMINALS = 8
MAX_PER_PROJECT = 3
MAX_INPUT_BYTES = 16_384
MAX_OUTPUT_BYTES = 524_288
SESSION_IDLE_SECONDS = 8 * 60 * 60


class DeveloperTerminalError(RuntimeError):
    pass


class DeveloperTerminalManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _shell_spec(choice: str) -> tuple[list[str], str]:
        choice = (choice or "auto").strip().lower()
        if os.name == "nt":
            choices = {
                "auto": ("powershell", ["-NoLogo", "-NoProfile"]),
                "powershell": ("powershell", ["-NoLogo", "-NoProfile"]),
                "pwsh": ("pwsh", ["-NoLogo", "-NoProfile"]),
                "cmd": ("cmd", ["/Q", "/D"]),
            }
        else:
            default_shell = "bash" if shutil.which("bash") else "sh"
            # Pipe-backed command streams are intentionally non-interactive.  They
            # preserve shell state between submitted commands without fake TTY
            # warnings; full-screen TUI applications still require PTY/ConPTY.
            choices = {
                "auto": (default_shell, ["--noprofile", "--norc"] if default_shell == "bash" else []),
                "bash": ("bash", ["--noprofile", "--norc"]),
                "zsh": ("zsh", ["-f"]),
                "sh": ("sh", []),
            }
        if choice not in choices:
            raise ValueError("Unsupported terminal shell selection.")
        name, args = choices[choice]
        executable = name if os.path.isabs(name) else shutil.which(name)
        if not executable or not Path(executable).is_file():
            raise DeveloperTerminalError(f"Shell '{name}' was not found on PATH.")
        return [str(executable), *args], Path(executable).name

    def open(self, project_id: str, project_root: Path, shell: str = "auto") -> dict[str, Any]:
        root = Path(project_root).resolve(strict=True)
        if not root.is_dir() or root.is_symlink():
            raise ValueError("Project terminal root is not a valid directory.")
        argv, shell_name = self._shell_spec(shell)
        with self._lock:
            self._reap_locked()
            if len(self._sessions) >= MAX_TERMINALS:
                raise DeveloperTerminalError(f"Terminal session limit reached ({MAX_TERMINALS}).")
            project_count = sum(1 for s in self._sessions.values() if s["project_id"] == project_id and s["process"].poll() is None)
            if project_count >= MAX_PER_PROJECT:
                raise DeveloperTerminalError(f"This project already has {MAX_PER_PROJECT} active terminals.")
            env = {k: v for k, v in os.environ.items() if k in {
                "PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC", "HOME", "USERPROFILE",
                "USERNAME", "USERDOMAIN", "PSModulePath", "APPDATA", "LOCALAPPDATA",
                "TEMP", "TMP", "LANG", "LC_ALL", "TERM",
            }}
            env.setdefault("TERM", "dumb")
            if os.name != "nt":
                env.setdefault("PS1", "cf> ")
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
            proc = subprocess.Popen(
                argv, cwd=str(root), env=env, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=0, close_fds=(os.name != "nt"), creationflags=creationflags,
                start_new_session=(os.name != "nt"),
            )
            sid = "TERM-" + uuid.uuid4().hex[:20]
            session: dict[str, Any] = {
                "id": sid, "project_id": project_id, "shell": shell_name,
                "cwd": str(root), "process": proc, "created": time.time(),
                "last_activity": time.time(), "chunks": deque(), "bytes": 0,
                "base_offset": 0, "closed": False, "reader_error": None,
            }
            self._sessions[sid] = session
            thread = threading.Thread(target=self._reader, args=(sid,), daemon=True, name=f"CF-Terminal-{sid[-6:]}")
            session["reader"] = thread
            thread.start()
            return {"session_id": sid, "project_id": project_id, "shell": shell_name,
                    "cwd": str(root), "pid": proc.pid, "status": "running",
                    "notice": "Local host shell opened at the selected project directory. It is not sandboxed; commands run with the CyberForge user's OS permissions.",
                    "backend": "pipe", "pty_available": False,
                    "terminal_limit": "Pipe-backed shell. Full-screen TUI programs requiring PTY/ConPTY are not supported in this build."}

    def _reader(self, sid: str) -> None:
        while True:
            with self._lock:
                session = self._sessions.get(sid)
                if not session:
                    return
                proc = session["process"]
                stream = proc.stdout
            if stream is None:
                return
            try:
                chunk = stream.read1(4096) if hasattr(stream, "read1") else stream.read(4096)
            except Exception as exc:
                with self._lock:
                    if sid in self._sessions:
                        self._sessions[sid]["reader_error"] = type(exc).__name__
                return
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", "replace")
            with self._lock:
                current = self._sessions.get(sid)
                if not current:
                    return
                current["chunks"].append(bytes(chunk))
                current["bytes"] += len(chunk)
                current["last_activity"] = time.time()
                while current["bytes"] > MAX_OUTPUT_BYTES and current["chunks"]:
                    removed = current["chunks"].popleft()
                    current["bytes"] -= len(removed)
                    current["base_offset"] += len(removed)

    def _get_locked(self, sid: str, project_id: str | None = None) -> dict[str, Any]:
        session = self._sessions.get(sid)
        if not session or session["closed"]:
            raise FileNotFoundError("Terminal session was not found or has closed.")
        if project_id and session["project_id"] != project_id:
            raise PermissionError("Terminal session does not belong to this project.")
        return session

    def write(self, sid: str, project_id: str, data: str) -> dict[str, Any]:
        if not isinstance(data, str) or not data or len(data.encode("utf-8")) > MAX_INPUT_BYTES or "\x00" in data:
            raise ValueError("Terminal input must be non-empty UTF-8 text under 16 KiB without NUL bytes.")
        with self._lock:
            session = self._get_locked(sid, project_id)
            proc = session["process"]
            if proc.poll() is not None or proc.stdin is None:
                raise DeveloperTerminalError("Terminal shell is no longer running.")
            try:
                proc.stdin.write(data.encode("utf-8"))
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                raise DeveloperTerminalError("Terminal input pipe is closed.") from None
            session["last_activity"] = time.time()
            return {"sent_bytes": len(data.encode("utf-8")), "status": "sent"}

    def read(self, sid: str, project_id: str | None, offset: int = 0) -> dict[str, Any]:
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("Terminal output offset must be a non-negative integer.")
        with self._lock:
            session = self._get_locked(sid, project_id)
            chunks = list(session["chunks"])
            full = b"".join(chunks)
            base = session["base_offset"]
            end = base + len(full)
            requested = max(base, offset)
            start_index = requested - base
            data = full[start_index:]
            proc = session["process"]
            status = "running" if proc.poll() is None else "exited"
            session["last_activity"] = time.time()
            return {"session_id": sid, "project_id": session["project_id"],
                    "shell": session["shell"], "cwd": session["cwd"],
                    "pid": proc.pid, "status": status, "exit_code": proc.poll(),
                    "output": data.decode("utf-8", "replace"), "offset": end,
                    "truncated": offset < base, "base_offset": base,
                    "reader_error": session["reader_error"]}

    def interrupt(self, sid: str, project_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            session = self._get_locked(sid, project_id)
            proc = session["process"]
            if proc.poll() is not None:
                return {"interrupted": False, "status": "exited"}
            try:
                if os.name == "nt":
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    os.killpg(proc.pid, signal.SIGINT)
            except (OSError, ProcessLookupError) as exc:
                raise DeveloperTerminalError("Could not deliver an interrupt signal to this terminal session.") from exc
            session["last_activity"] = time.time()
            return {"interrupted": True, "session_id": sid, "signal": "CTRL_BREAK" if os.name == "nt" else "SIGINT"}

    @staticmethod
    def _terminate_tree(proc: subprocess.Popen[bytes], timeout: float = 2.0) -> None:
        if proc.poll() is not None:
            return
        if os.name == "nt":
            taskkill = shutil.which("taskkill")
            if taskkill:
                try:
                    subprocess.run([taskkill, "/PID", str(proc.pid), "/T", "/F"],
                                   capture_output=True, timeout=5, check=False)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if proc.poll() is None:
                try: proc.terminate()
                except OSError: pass
        else:
            try: os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError: return
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                try: proc.kill()
                except OSError: pass
            else:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            try: proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired: pass

    def close(self, sid: str, project_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            session = self._get_locked(sid, project_id)
            proc = session["process"]
            session["closed"] = True
            self._sessions.pop(sid, None)
        try:
            self._terminate_tree(proc)
        finally:
            for pipe in (proc.stdin, proc.stdout):
                try:
                    if pipe: pipe.close()
                except OSError:
                    pass
        return {"closed": True, "session_id": sid}

    def list_sessions(self, project_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            self._reap_locked()
            rows = []
            for s in self._sessions.values():
                if project_id and s["project_id"] != project_id:
                    continue
                p = s["process"]
                rows.append({"session_id": s["id"], "project_id": s["project_id"],
                             "shell": s["shell"], "cwd": s["cwd"], "pid": p.pid,
                             "status": "running" if p.poll() is None else "exited",
                             "created_at": s["created"], "last_activity": s["last_activity"]})
            return rows

    def _reap_locked(self) -> None:
        now = time.time()
        stale = [sid for sid, s in self._sessions.items()
                 if (now - s["last_activity"] > SESSION_IDLE_SECONDS) or s["closed"]]
        for sid in stale:
            session = self._sessions.pop(sid, None)
            if not session:
                continue
            proc = session["process"]
            self._terminate_tree(proc)
            for pipe in (proc.stdin, proc.stdout):
                try:
                    if pipe: pipe.close()
                except OSError: pass


def capabilities() -> dict[str, Any]:
    return {
        "version": "1.9.6",
        "editor": {"engine": "Monaco Editor", "pinned_version": "0.57.0",
                   "local_vendor_supported": True, "cdn_fallback": True,
                   "fallback_editor": "built-in textarea editor"},
        "terminal": {"sessions_max": MAX_TERMINALS, "sessions_per_project": MAX_PER_PROJECT,
                     "output_buffer_bytes": MAX_OUTPUT_BYTES, "explicit_start": True,
                     "backend": "pipe", "pty_available": False,
                     "runs_with_host_user_permissions": True,
                     "notice": "Full-screen TUI applications requiring PTY/ConPTY are not supported."},
        "features": ["Monaco code editor", "project file operations with recoverable trash",
                     "integrated local terminal", "command palette", "keyboard shortcuts",
                     "language-aware editor services", "Git and AI patch integration"],
    }
