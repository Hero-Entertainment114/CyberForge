"""v1.9.7: LSP and Python DAP adapters for the local-first Dev Studio.

External language servers/debug adapters are fixed-profile local processes. They
run with the CyberForge OS user's permissions, are NOT sandboxed, and require an
explicit code_execution grant. Server-originated edits/commands and DAP reverse
requests are rejected; arbitrary executables/adapter arguments are not accepted.
"""
from __future__ import annotations
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

VERSION = "1.9.7"
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 1000
MAX_LSP_SESSIONS = 8
MAX_DAP_SESSIONS = 4

LSP_PROFILES: dict[str, list[dict[str, Any]]] = {
    "python": [
        {"id": "pyright", "exe": "pyright-langserver", "args": ["--stdio"]},
        {"id": "basedpyright", "exe": "basedpyright-langserver", "args": ["--stdio"]},
        {"id": "pylsp", "exe": "pylsp", "args": []},
    ],
    "javascript": [{"id": "typescript", "exe": "typescript-language-server", "args": ["--stdio"]}],
    "typescript": [{"id": "typescript", "exe": "typescript-language-server", "args": ["--stdio"]}],
    "javascriptreact": [{"id": "typescript", "exe": "typescript-language-server", "args": ["--stdio"]}],
    "typescriptreact": [{"id": "typescript", "exe": "typescript-language-server", "args": ["--stdio"]}],
    "c": [{"id": "clangd", "exe": "clangd", "args": ["--background-index"]}],
    "cpp": [{"id": "clangd", "exe": "clangd", "args": ["--background-index"]}],
    "rust": [{"id": "rust-analyzer", "exe": "rust-analyzer", "args": []}],
    "go": [{"id": "gopls", "exe": "gopls", "args": []}],
    "json": [{"id": "jsonls", "exe": "vscode-json-language-server", "args": ["--stdio"]}],
    "html": [{"id": "html", "exe": "vscode-html-language-server", "args": ["--stdio"]}],
    "css": [{"id": "css", "exe": "vscode-css-language-server", "args": ["--stdio"]}],
    "bash": [{"id": "bashls", "exe": "bash-language-server", "args": ["start"]}],
}
LSP_METHODS = {
    "completion": "textDocument/completion", "hover": "textDocument/hover",
    "definition": "textDocument/definition", "references": "textDocument/references",
    "documentSymbol": "textDocument/documentSymbol", "signatureHelp": "textDocument/signatureHelp",
    "formatting": "textDocument/formatting", "rename": "textDocument/rename",
    "codeAction": "textDocument/codeAction",
}
DAP_METHODS = {"threads", "stackTrace", "scopes", "variables", "continue", "next", "stepIn",
               "stepOut", "pause", "evaluate", "setVariable", "terminate", "disconnect", "exceptionInfo"}


def safe_child_env() -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC", "HOME", "USERPROFILE", "USERNAME",
               "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "LANG", "LC_ALL", "VIRTUAL_ENV"}
    env = {k: v for k, v in os.environ.items() if k in allowed and isinstance(v, str)}
    env["PYTHONUNBUFFERED"] = "1"
    return env


def safe_root(root: Path) -> Path:
    raw = Path(root)
    if raw.is_symlink():
        raise PermissionError("Project root cannot be a symbolic link.")
    result = raw.resolve(strict=True)
    if not result.is_dir():
        raise ValueError("Project workspace must be a directory.")
    return result


def safe_relative(value: Any) -> str:
    raw = str(value or "").replace("\\", "/").strip()
    if not raw or len(raw) > 240 or raw.startswith("/") or (len(raw) > 1 and raw[1] == ":") or "\x00" in raw:
        raise ValueError("A valid project-relative file path is required.")
    parts = raw.split("/")
    if any(x in {"", ".", ".."} for x in parts):
        raise ValueError("Project path traversal is not allowed.")
    lowered = [x.lower() for x in parts]
    if any(x in {".git", ".cf-trash", "node_modules", ".venv", "venv", "__pycache__"} for x in lowered):
        raise PermissionError("Internal and dependency directories are excluded from protocol access.")
    if any(x == ".env" or x.startswith(".env.") and x != ".env.example" for x in lowered):
        raise PermissionError("Environment secret files are excluded from protocol access.")
    return "/".join(parts)


def safe_project_file(root: Path, relative: Any) -> tuple[str, Path]:
    root = safe_root(root)
    rel = safe_relative(relative)
    target = root.joinpath(*rel.split("/"))
    current = root
    for part in rel.split("/"):
        current = current / part
        if current.exists() and current.is_symlink():
            raise PermissionError("Symbolic links are not allowed in LSP/DAP project paths.")
    path = target.resolve(strict=True)
    if path != root and root not in path.parents:
        raise PermissionError("Path escapes selected project workspace.")
    if not path.is_file():
        raise ValueError("Selected path is not a regular file.")
    return rel, path


class FramedProcess:
    """Small bounded Content-Length transport for LSP JSON-RPC and DAP."""
    def __init__(self, process: subprocess.Popen[bytes], protocol: str):
        self.process, self.protocol = process, protocol
        self.write_lock = threading.Lock()
        self.lock = threading.RLock()
        self.next_id = 1
        self.pending: dict[int, tuple[threading.Event, dict[str, Any]]] = {}
        self.events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self.buffer = bytearray()
        self.closed = False
        self.reader = threading.Thread(target=self._read_loop, daemon=True, name=f"CF-{protocol}-{process.pid}")
        self.reader.start()

    def send(self, message: dict[str, Any]) -> None:
        if self.process.poll() is not None or self.process.stdin is None:
            raise RuntimeError("Protocol process is not running.")
        body = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_FRAME_BYTES:
            raise ValueError("Protocol frame exceeds 8 MiB.")
        frame = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
        with self.write_lock:
            self.process.stdin.write(frame)
            self.process.stdin.flush()

    def notify(self, method: str, params: Any = None) -> None:
        if self.protocol != "lsp":
            raise RuntimeError("Notifications are only available for LSP transport.")
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)

    def request(self, method: str, params: Any = None, timeout: float = 12.0, wait: bool = True):
        with self.lock:
            seq = self.next_id
            self.next_id += 1
            event, box = threading.Event(), {}
            self.pending[seq] = (event, box)
        if self.protocol == "lsp":
            msg = {"jsonrpc": "2.0", "id": seq, "method": method}
            if params is not None: msg["params"] = params
        else:
            msg = {"seq": seq, "type": "request", "command": method}
            if params is not None: msg["arguments"] = params
        try:
            self.send(msg)
        except Exception:
            with self.lock: self.pending.pop(seq, None)
            raise
        return (seq, None) if not wait else (seq, self.wait_response(seq, timeout))

    def wait_response(self, seq: int, timeout: float = 12.0):
        with self.lock: pair = self.pending.get(seq)
        if pair is None: raise RuntimeError("Protocol request no longer pending.")
        event, box = pair
        if not event.wait(max(.1, min(float(timeout), 60.0))):
            with self.lock: self.pending.pop(seq, None)
            raise TimeoutError(f"{self.protocol.upper()} request timed out.")
        with self.lock: self.pending.pop(seq, None)
        if box.get("error"):
            raise RuntimeError(str(box["error"].get("message", "Protocol error"))[:1000])
        if self.protocol == "dap" and not box.get("success", False):
            raise RuntimeError(str(box.get("message", "DAP request failed"))[:1000])
        return box.get("result") if self.protocol == "lsp" else box.get("body", {})

    def wait_event(self, name: str, timeout: float = 8.0):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            with self.lock:
                for i, event in enumerate(self.events):
                    key = event.get("method") if self.protocol == "lsp" else event.get("event")
                    if key == name:
                        del self.events[i]
                        return event
            if self.process.poll() is not None: return None
            time.sleep(.025)
        return None

    def drain(self, limit: int = 200):
        limit = max(1, min(int(limit), 500))
        with self.lock:
            out = []
            while self.events and len(out) < limit: out.append(self.events.popleft())
            return out

    def _dispatch(self, msg: dict[str, Any]):
        if self.protocol == "lsp":
            if "id" in msg and ("result" in msg or "error" in msg):
                with self.lock:
                    pair = self.pending.get(msg.get("id"))
                    if pair: pair[1].update(msg); pair[0].set()
                return
            if "id" in msg and "method" in msg:
                method = msg.get("method")
                if method == "workspace/applyEdit": result = {"applied": False, "failureReason": "Review server edits in CyberForge before applying."}
                elif method == "workspace/configuration": result = [{} for _ in ((msg.get("params") or {}).get("items", []))]
                elif method == "client/registerCapability": result = None
                else:
                    self.send({"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32601, "message": "Server-initiated requests are disabled."}})
                    return
                self.send({"jsonrpc": "2.0", "id": msg.get("id"), "result": result})
            elif msg.get("method"):
                with self.lock: self.events.append(msg)
            return
        if msg.get("type") == "response":
            with self.lock:
                pair = self.pending.get(msg.get("request_seq"))
                if pair: pair[1].update(msg); pair[0].set()
        elif msg.get("type") == "event":
            with self.lock: self.events.append(msg)
        elif msg.get("type") == "request":
            with self.lock: seq = self.next_id; self.next_id += 1
            self.send({"seq": seq, "type": "response", "request_seq": msg.get("seq"),
                       "command": msg.get("command", ""), "success": False,
                       "message": "Reverse adapter requests such as runInTerminal are disabled."})

    def _read_loop(self):
        stream = self.process.stdout
        if stream is None: return
        try:
            while not self.closed:
                chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
                if not chunk: break
                self.buffer.extend(chunk)
                while True:
                    mark = self.buffer.find(b"\r\n\r\n")
                    if mark < 0:
                        if len(self.buffer) > 8192: raise ValueError("Protocol header exceeds 8 KiB.")
                        break
                    header = bytes(self.buffer[:mark]).decode("ascii", "replace")
                    length = next((int(x.split(":", 1)[1].strip()) for x in header.split("\r\n") if x.lower().startswith("content-length:")), None)
                    if length is None or length < 0 or length > MAX_FRAME_BYTES: raise ValueError("Invalid Content-Length frame.")
                    end = mark + 4 + length
                    if len(self.buffer) < end: break
                    raw = bytes(self.buffer[mark + 4:end]); del self.buffer[:end]
                    message = json.loads(raw.decode("utf-8"))
                    if isinstance(message, dict): self._dispatch(message)
        except Exception as exc:
            with self.lock: self.events.append({"method" if self.protocol == "lsp" else "event": "cyberforge/protocolError",
                                                 "params" if self.protocol == "lsp" else "body": {"error": type(exc).__name__}})
        finally:
            with self.lock:
                self.closed = True
                for event, box in self.pending.values(): box.setdefault("error", {"message": "Protocol process exited."}); event.set()

    def close(self):
        self.closed = True
        # Stop the process tree, not only the protocol parent. On Windows taskkill
        # is invoked with a fixed argv (never through a shell) for CREATE_NEW_PROCESS_GROUP.
        try:
            if self.process.poll() is None:
                if os.name != "nt":
                    os.killpg(self.process.pid, signal.SIGTERM)
                    self.process.wait(timeout=2)
                else:
                    system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
                    taskkill = str(Path(system_root) / "System32" / "taskkill.exe")
                    if Path(taskkill).is_file():
                        subprocess.run([taskkill, "/PID", str(self.process.pid), "/T", "/F"],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=4, check=False)
                    else:
                        self.process.terminate()
                    self.process.wait(timeout=2)
        except Exception:
            try:
                if os.name != "nt": os.killpg(self.process.pid, signal.SIGKILL)
                else: self.process.kill()
            except Exception: pass
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            try:
                if stream: stream.close()
            except Exception: pass


class LanguageServerManager:
    def __init__(self): self.lock = threading.RLock(); self.sessions: dict[str, dict[str, Any]] = {}

    @staticmethod
    def inventory():
        rows = []
        for lang, profiles in LSP_PROFILES.items():
            for profile in profiles:
                path = shutil.which(profile["exe"])
                rows.append({"language": lang, "server": profile["id"], "executable": profile["exe"], "available": bool(path), "path": path})
        return {"protocol": "LSP 3.x / JSON-RPC 2.0", "languages": rows,
                "notice": "Inventory does not execute tools. Starting a server requires approval and executes a local binary with OS-user permissions."}

    def start(self, project_id: str, root: Path, language: str, acknowledged: bool):
        if acknowledged is not True: raise PermissionError("Confirm starting a local language server first.")
        root = safe_root(root); language = str(language or "").lower().strip()
        profiles = LSP_PROFILES.get(language)
        if not profiles: raise ValueError("No built-in LSP profile for this language.")
        profile = next((p for p in profiles if shutil.which(p["exe"])), None)
        if not profile: raise FileNotFoundError("No supported language server installed for this language.")
        executable = Path(shutil.which(profile["exe"])).resolve(strict=True)
        if executable == root or root in executable.parents:
            raise PermissionError("A project-local executable cannot be launched as a language server.")
        with self.lock:
            self._reap()
            if len(self.sessions) >= MAX_LSP_SESSIONS: raise RuntimeError("LSP session limit reached.")
            if any(s["project_id"] == project_id and s["language"] == language for s in self.sessions.values()):
                raise RuntimeError("This project already has an LSP session for the language.")
            exe = str(executable)
            flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
            proc = subprocess.Popen([exe, *profile["args"]], cwd=str(root), env=safe_child_env(),
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    bufsize=0, close_fds=(os.name != "nt"), creationflags=flags,
                                    start_new_session=(os.name != "nt"))
            transport = FramedProcess(proc, "lsp"); sid = "LSP-" + uuid.uuid4().hex[:18]
            session = {"id": sid, "project_id": project_id, "root": root, "language": language,
                       "server": profile["id"], "process": proc, "transport": transport, "documents": {}, "capabilities": {}}
            self.sessions[sid] = session
        try:
            result = transport.request("initialize", {
                "processId": os.getpid(), "clientInfo": {"name": "CyberForge Dev Studio", "version": VERSION},
                "rootUri": root.as_uri(), "rootPath": str(root),
                "workspaceFolders": [{"uri": root.as_uri(), "name": root.name}],
                "capabilities": {"workspace": {"workspaceFolders": True, "configuration": True, "applyEdit": False},
                    "textDocument": {"completion": {"completionItem": {"snippetSupport": False}},
                    "hover": {"contentFormat": ["markdown", "plaintext"]}, "definition": {"linkSupport": True},
                    "references": {}, "documentSymbol": {"hierarchicalDocumentSymbolSupport": True},
                    "rename": {"prepareSupport": True}, "publishDiagnostics": {"relatedInformation": True}}},
                "trace": "off"}, timeout=20)[1]
            session["capabilities"] = result.get("capabilities", {}) if isinstance(result, dict) else {}
            transport.notify("initialized", {})
            return {"session_id": sid, "project_id": project_id, "language": language, "server": profile["id"],
                    "pid": proc.pid, "status": "running", "workspace_root": str(root), "capabilities": session["capabilities"],
                    "notice": "Server runs locally with OS-user permissions and can read the project. Server-initiated edits and commands are disabled."}
        except Exception:
            self.stop(sid, project_id); raise

    def _session(self, sid: str, project_id: str | None = None):
        with self.lock: session = self.sessions.get(sid)
        if not session: raise FileNotFoundError("LSP session not found.")
        if project_id and session["project_id"] != project_id: raise PermissionError("LSP session belongs to another project.")
        if session["process"].poll() is not None: raise RuntimeError("LSP server exited.")
        return session

    def open_document(self, sid: str, project_id: str, relative: str, language_id: str, text: str):
        s = self._session(sid, project_id); rel, path = safe_project_file(s["root"], relative)
        if not isinstance(text, str) or len(text.encode("utf-8")) > 1_000_000: raise ValueError("Document text exceeds 1 MB or is invalid.")
        uri = path.as_uri(); previous = s["documents"].get(rel); version = (previous or {}).get("version", 0) + 1
        if previous:
            s["transport"].notify("textDocument/didChange", {"textDocument": {"uri": uri, "version": version}, "contentChanges": [{"text": text}]})
        else:
            s["transport"].notify("textDocument/didOpen", {"textDocument": {"uri": uri, "languageId": str(language_id)[:48], "version": version, "text": text}})
        s["documents"][rel] = {"uri": uri, "version": version}
        return {"opened": True, "path": rel, "version": version}

    def request(self, sid: str, project_id: str, relative: str, method: str, line: int, character: int, new_name: str = ""):
        if method not in LSP_METHODS: raise ValueError("LSP method is not enabled.")
        s = self._session(sid, project_id); rel, path = safe_project_file(s["root"], relative)
        doc = s["documents"].get(rel)
        if not doc: raise ValueError("Open the document in LSP before using language features.")
        line = max(0, min(int(line), 1_000_000)); character = max(0, min(int(character), 1_000_000))
        pos = {"line": line, "character": character}; td = {"uri": doc["uri"]}
        params: dict[str, Any] = {"textDocument": td, "position": pos}
        if method == "references": params["context"] = {"includeDeclaration": True}
        elif method == "formatting": params = {"textDocument": td, "options": {"tabSize": 4, "insertSpaces": True}}
        elif method == "rename":
            if not new_name or len(new_name) > 160 or "\x00" in new_name: raise ValueError("A valid new symbol name is required.")
            params["newName"] = new_name
        elif method == "codeAction":
            params["range"] = {"start": pos, "end": {"line": line, "character": character + 1}}
            params["context"] = {"diagnostics": []}
        _, result = s["transport"].request(LSP_METHODS[method], params, timeout=12)
        if len(json.dumps(result, ensure_ascii=False, default=str).encode("utf-8")) > 2_000_000: raise ValueError("LSP result exceeds 2 MB.")
        return {"method": method, "path": rel, "result": result, "server": s["server"]}

    def events(self, sid: str, project_id: str, limit: int = 200):
        s = self._session(sid, project_id)
        return {"session_id": sid, "status": "running", "events": s["transport"].drain(limit)}

    def list_sessions(self, project_id: str | None = None):
        with self.lock:
            return [{"session_id": s["id"], "project_id": s["project_id"], "language": s["language"], "server": s["server"], "pid": s["process"].pid,
                     "status": "running" if s["process"].poll() is None else "exited"} for s in self.sessions.values() if not project_id or s["project_id"] == project_id]

    def stop(self, sid: str, project_id: str | None = None):
        with self.lock: s = self.sessions.get(sid)
        if not s: return {"stopped": False}
        if project_id and s["project_id"] != project_id: raise PermissionError("LSP session belongs to another project.")
        with self.lock: self.sessions.pop(sid, None)
        try: s["transport"].request("shutdown", {}, timeout=2); s["transport"].notify("exit", {})
        except Exception: pass
        s["transport"].close()
        return {"stopped": True, "session_id": sid}

    def _reap(self):
        for sid, s in list(self.sessions.items()):
            if s["process"].poll() is not None:
                self.sessions.pop(sid, None)
                try: s["transport"].close()
                except Exception: pass


class DebugAdapterManager:
    """A narrowly scoped Python debugpy DAP client; not a generic shell/adapter runner."""
    def __init__(self): self.lock = threading.RLock(); self.sessions: dict[str, dict[str, Any]] = {}

    @staticmethod
    def inventory():
        available = importlib.util.find_spec("debugpy") is not None
        return {"protocol": "DAP 1.x", "adapters": [{"id": "python-debugpy", "language": "python", "available": available,
                "command": f"{sys.executable} -m debugpy.adapter" if available else None}],
                "notice": "Only the built-in Python debugpy adapter is enabled. Debuggee execution requires explicit approval and uses host-user permissions."}

    def start_python(self, project_id: str, root: Path, program: str, args: list[str] | None, breakpoints: list[int] | None, acknowledged: bool):
        if acknowledged is not True: raise PermissionError("Authorize running this Python program under the local debugger.")
        root = safe_root(root); rel, path = safe_project_file(root, program)
        if path.suffix.lower() not in {".py", ".pyw"}: raise ValueError("Python debugger accepts only .py/.pyw files.")
        if importlib.util.find_spec("debugpy") is None: raise FileNotFoundError("Install debugpy into CyberForge's active Python environment first.")
        args = args or []
        if not isinstance(args, list) or len(args) > 64 or any(not isinstance(x, str) or len(x) > 1000 or "\x00" in x for x in args):
            raise ValueError("Debug arguments must be up to 64 bounded strings.")
        lines = sorted(set(int(x) for x in (breakpoints or [])))
        if len(lines) > 500 or any(x < 1 or x > 1_000_000 for x in lines): raise ValueError("Invalid breakpoint list.")
        with self.lock:
            self._reap()
            if len(self.sessions) >= MAX_DAP_SESSIONS: raise RuntimeError("DAP session limit reached.")
            if any(s["project_id"] == project_id for s in self.sessions.values()): raise RuntimeError("A debugger is already active for this project.")
            proc = subprocess.Popen([sys.executable, "-m", "debugpy.adapter"], cwd=str(root), env=safe_child_env(),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
                close_fds=(os.name != "nt"), creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0,
                start_new_session=(os.name != "nt"))
            transport = FramedProcess(proc, "dap"); sid = "DAP-" + uuid.uuid4().hex[:18]
            s = {"id": sid, "project_id": project_id, "root": root, "program": rel, "path": str(path), "process": proc, "transport": transport}
            self.sessions[sid] = s
        try:
            _, caps = transport.request("initialize", {"clientID": "cyberforge", "clientName": "CyberForge Dev Studio",
                "adapterID": "debugpy", "pathFormat": "path", "linesStartAt1": True, "columnsStartAt1": True,
                "supportsRunInTerminalRequest": False, "supportsVariableType": True, "supportsVariablePaging": True,
                "supportsStartDebuggingRequest": False}, timeout=15)
            launch_id, _ = transport.request("launch", {"noDebug": False, "program": str(path), "cwd": str(root),
                "args": args, "console": "internalConsole", "justMyCode": True, "stopOnEntry": True,
                "redirectOutput": True, "python": sys.executable}, wait=False)
            if transport.wait_event("initialized", 15) is None: raise TimeoutError("DAP adapter did not initialize.")
            _, bp = transport.request("setBreakpoints", {"source": {"name": path.name, "path": str(path)},
                "breakpoints": [{"line": x} for x in lines], "sourceModified": False}, timeout=10)
            transport.request("setExceptionBreakpoints", {"filters": ["raised", "uncaught"]}, timeout=8)
            transport.request("configurationDone", {}, timeout=8)
            transport.wait_response(launch_id, 25)
            return {"session_id": sid, "project_id": project_id, "adapter": "debugpy", "pid": proc.pid,
                "program": rel, "status": "running", "breakpoints": (bp or {}).get("breakpoints", []), "capabilities": caps or {},
                "notice": "The debuggee runs locally with OS-user permissions, not in the malware sandbox."}
        except Exception:
            self.stop(sid, project_id); raise

    def _session(self, sid: str, project_id: str | None = None):
        with self.lock: s = self.sessions.get(sid)
        if not s: raise FileNotFoundError("DAP session not found.")
        if project_id and s["project_id"] != project_id: raise PermissionError("DAP session belongs to another project.")
        if s["process"].poll() is not None: raise RuntimeError("DAP adapter exited.")
        return s

    def command(self, sid: str, project_id: str, command: str, payload: dict[str, Any] | None, acknowledged: bool):
        if command not in DAP_METHODS: raise ValueError("DAP command is not enabled.")
        if command in {"evaluate", "setVariable", "terminate", "disconnect"} and acknowledged is not True:
            raise PermissionError("This debugger command requires explicit approval.")
        s = self._session(sid, project_id); p = payload or {}; a: dict[str, Any] = {}
        if command == "stackTrace": a = {"threadId": max(1, int(p.get("thread_id", 1))), "startFrame": 0, "levels": 100}
        elif command == "scopes": a = {"frameId": max(0, int(p.get("frame_id", 0)))}
        elif command == "variables": a = {"variablesReference": max(0, int(p.get("variables_reference", 0))), "filter": "named", "start": 0, "count": 500}
        elif command in {"continue", "next", "stepIn", "stepOut", "pause"}: a = {"threadId": max(1, int(p.get("thread_id", 1)))}
        elif command == "evaluate":
            expr = str(p.get("expression", ""))
            if not expr or len(expr) > 500 or "\x00" in expr: raise ValueError("Expression is empty or too long.")
            a = {"expression": expr, "frameId": max(0, int(p.get("frame_id", 0))), "context": "repl"}
        elif command == "setVariable":
            name, value = str(p.get("name", "")), str(p.get("value", ""))
            if not name or len(name) > 200 or len(value) > 1000 or "\x00" in name + value: raise ValueError("Variable name/value invalid.")
            a = {"variablesReference": max(0, int(p.get("variables_reference", 0))), "name": name, "value": value}
        elif command == "exceptionInfo": a = {"threadId": max(1, int(p.get("thread_id", 1)))}
        elif command in {"terminate", "disconnect"}: a = {"restart": False, "terminateDebuggee": True}
        _, result = s["transport"].request(command, a, timeout=10)
        if command in {"terminate", "disconnect"}: self.stop(sid, project_id, send_disconnect=False)
        return {"session_id": sid, "command": command, "body": result or {}}

    def events(self, sid: str, project_id: str, limit: int = 200):
        s = self._session(sid, project_id)
        return {"session_id": sid, "status": "running", "events": s["transport"].drain(limit)}

    def stop(self, sid: str, project_id: str | None = None, send_disconnect: bool = True):
        with self.lock: s = self.sessions.get(sid)
        if not s: return {"stopped": False}
        if project_id and s["project_id"] != project_id: raise PermissionError("DAP session belongs to another project.")
        with self.lock: self.sessions.pop(sid, None)
        if send_disconnect and s["process"].poll() is None:
            try: s["transport"].request("disconnect", {"restart": False, "terminateDebuggee": True}, timeout=3)
            except Exception: pass
        s["transport"].close()
        return {"stopped": True, "session_id": sid}

    def list_sessions(self, project_id: str | None = None):
        with self.lock:
            return [{"session_id": s["id"], "project_id": s["project_id"], "program": s["program"], "pid": s["process"].pid,
                "status": "running" if s["process"].poll() is None else "exited"} for s in self.sessions.values() if not project_id or s["project_id"] == project_id]

    def _reap(self):
        for sid, s in list(self.sessions.items()):
            if s["process"].poll() is not None:
                self.sessions.pop(sid, None)
                try: s["transport"].close()
                except Exception: pass


def capabilities():
    inventory = LanguageServerManager.inventory(); dap = DebugAdapterManager.inventory()
    return {"version": VERSION, "lsp": {"protocol": inventory["protocol"], "servers": inventory["languages"],
            "available": sum(1 for x in inventory["languages"] if x["available"]), "features": sorted(LSP_METHODS),
            "explicit_permission": "code_execution"},
        "dap": {**dap, "commands": sorted(DAP_METHODS), "explicit_permission": "code_execution"},
        "git": {"operations": ["status", "diff", "staged-diff", "log", "branches", "stage", "unstage", "commit", "branch-create", "branch-switch", "identity"],
                "remote_operations": False, "hooks_disabled": True},
        "extension_architecture": {"providers": ["LSP", "DAP", "Git"], "vscode_vsix_execution": False,
            "notice": "Protocol-provider architecture is in place; arbitrary VS Code extension code is not executed."}}
