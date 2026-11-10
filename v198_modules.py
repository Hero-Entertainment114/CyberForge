"""CyberForge AIO v1.9.8: declarative extensions, multi-adapter DAP and PTY.

Extensions are declarative-only (themes/snippets/language metadata); VSIX
JavaScript entrypoints are never executed. Debug adapters and terminal shells
run locally with the OS user's permissions after explicit user approval.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from collections import deque
from pathlib import Path, PurePosixPath
from typing import Any

import v196_modules
import v197_modules

VERSION = "1.9.8"
MAX_EXTENSION_ARCHIVE = 12 * 1024 * 1024
MAX_EXTENSION_UNPACKED = 24 * 1024 * 1024
MAX_EXTENSION_ENTRIES = 300
MAX_EXTENSION_FILE = 4 * 1024 * 1024
MAX_EXTENSION_COUNT = 100
MAX_TERMINALS = 8
MAX_PER_PROJECT = 3
MAX_INPUT_BYTES = 16_384
MAX_OUTPUT_BYTES = 1_048_576
SESSION_IDLE_SECONDS = 8 * 60 * 60


class ExtensionManager:
    """Install a safe declarative subset of VSIX/CFEXT packages."""
    def __init__(self, data_dir: Path):
        base = Path(data_dir).expanduser().resolve()
        candidate = base / "dev_extensions"
        candidate.mkdir(parents=True, exist_ok=True)
        if candidate.is_symlink() or candidate.resolve().parent != base:
            raise PermissionError("The managed extension store cannot be a symlink or escape the data directory.")
        self.root = candidate.resolve()
        self.lock = threading.RLock()

    @staticmethod
    def _safe_entry(name: str) -> str:
        if not isinstance(name, str) or not name or len(name) > 240 or "\\" in name or "\x00" in name:
            raise ValueError("Extension archive contains an invalid entry name.")
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise PermissionError("Extension archive path traversal is not allowed.")
        return path.as_posix()

    @staticmethod
    def _read_json(zf: zipfile.ZipFile, name: str, limit: int = MAX_EXTENSION_FILE) -> Any:
        info = zf.getinfo(name)
        if info.file_size > limit:
            raise ValueError(f"Extension contribution is too large: {name}")
        return json.loads(zf.read(info).decode("utf-8"))

    def _parse_archive(self, raw: bytes) -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any]]:
        if not raw or len(raw) > MAX_EXTENSION_ARCHIVE:
            raise ValueError("Extension archive must be between 1 byte and 12 MiB.")
        try:
            zf = zipfile.ZipFile(__import__("io").BytesIO(raw))
        except (zipfile.BadZipFile, OSError):
            raise ValueError("Extension package must be a valid VSIX/CFEXT ZIP archive.") from None
        with zf:
            infos = zf.infolist()
            if len(infos) > MAX_EXTENSION_ENTRIES:
                raise ValueError("Extension contains too many archive entries.")
            total = 0
            entries: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                name = self._safe_entry(info.filename.rstrip("/")) if not info.is_dir() else self._safe_entry(info.filename.rstrip("/"))
                if name in entries:
                    raise ValueError("Extension archive contains duplicate paths.")
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise PermissionError("Symbolic links are not allowed inside extensions.")
                if info.file_size > MAX_EXTENSION_FILE:
                    raise ValueError("An extension file exceeds the 4 MiB per-file limit.")
                if info.compress_size and info.file_size > max(1, info.compress_size) * 100:
                    raise ValueError("Extension compression ratio exceeds the safety limit.")
                total += info.file_size
                if total > MAX_EXTENSION_UNPACKED:
                    raise ValueError("Extension unpacked size exceeds 24 MiB.")
                entries[name] = info
            manifest_name = "extension/package.json" if "extension/package.json" in entries else "package.json"
            if manifest_name not in entries:
                raise ValueError("VSIX/CFEXT package.json manifest was not found.")
            manifest = self._read_json(zf, manifest_name, 128 * 1024)
            if not isinstance(manifest, dict):
                raise ValueError("Extension manifest must be a JSON object.")
            # Any executable entry point disqualifies the package. No Node, web-worker,
            # activation hook, npm lifecycle, debugger, task or terminal contribution.
            forbidden = {"main", "browser", "activationEvents", "extensionDependencies", "scripts", "dependencies", "devDependencies"}
            present = sorted(forbidden.intersection(manifest.keys()))
            if present:
                raise PermissionError("Executable extension features are not supported: " + ", ".join(present))
            publisher = str(manifest.get("publisher", "")).strip().lower()
            name = str(manifest.get("name", "")).strip().lower()
            version = str(manifest.get("version", "")).strip()
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", publisher) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", name):
                raise ValueError("Extension publisher/name must use lowercase letters, digits and hyphens.")
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
                raise ValueError("Extension version must be SemVer compatible.")
            ext_id = f"{publisher}.{name}"
            contributes = manifest.get("contributes", {})
            if not isinstance(contributes, dict):
                raise ValueError("Extension contributes must be an object.")
            allowed_contrib = {"themes", "snippets", "languages"}
            unsupported = sorted(set(contributes) - allowed_contrib)
            if unsupported:
                raise PermissionError("Unsupported executable or unimplemented contribution types: " + ", ".join(unsupported))
            sanitized_assets: dict[str, bytes] = {}
            clean_contrib: dict[str, Any] = {"themes": [], "snippets": [], "languages": []}
            prefix = "extension/" if manifest_name.startswith("extension/") else ""
            for theme in contributes.get("themes", []):
                if not isinstance(theme, dict): raise ValueError("Theme contribution must be an object.")
                label = str(theme.get("label", "")).strip()[:80]
                path = self._safe_entry(prefix + str(theme.get("path", "")))
                if not label or not path.lower().endswith(".json") or path not in entries:
                    raise ValueError("Theme label/path is invalid or missing.")
                data = zf.read(entries[path])
                obj = json.loads(data.decode("utf-8"))
                if not isinstance(obj, dict) or len(data) > MAX_EXTENSION_FILE:
                    raise ValueError("Theme JSON is invalid.")
                if set(obj) - {"name", "type", "colors", "tokenColors", "semanticTokenColors", "semanticHighlighting", "include"}:
                    raise PermissionError("Theme contains unsupported fields.")
                if obj.get("include"):
                    raise PermissionError("Theme inheritance is not supported; bundled files only.")
                sanitized_assets[path] = data
                clean_contrib["themes"].append({"label": label, "path": path, "uiTheme": theme.get("uiTheme", "vs-dark")})
            for snippet in contributes.get("snippets", []):
                if not isinstance(snippet, dict): raise ValueError("Snippet contribution must be an object.")
                language = str(snippet.get("language", "")).strip().lower()
                path = self._safe_entry(prefix + str(snippet.get("path", "")))
                if not re.fullmatch(r"[a-z0-9_+#.-]{1,40}", language) or not path.lower().endswith(".json") or path not in entries:
                    raise ValueError("Snippet language/path is invalid or missing.")
                data = zf.read(entries[path]); obj = json.loads(data.decode("utf-8"))
                if not isinstance(obj, dict) or len(obj) > 500:
                    raise ValueError("Snippet JSON is invalid or contains too many entries.")
                for key, item in obj.items():
                    if not isinstance(key, str) or not isinstance(item, dict): raise ValueError("Snippet entry is invalid.")
                    body = item.get("body", "")
                    if not (isinstance(body, str) or isinstance(body, list) and all(isinstance(x, str) for x in body)):
                        raise ValueError("Snippet body must be text or a list of text lines.")
                    if len(json.dumps(item, ensure_ascii=False)) > 12_000: raise ValueError("Snippet entry exceeds its size limit.")
                sanitized_assets[path] = data
                clean_contrib["snippets"].append({"language": language, "path": path})
            for lang in contributes.get("languages", []):
                if not isinstance(lang, dict): raise ValueError("Language contribution must be an object.")
                lid = str(lang.get("id", "")).strip().lower()
                exts = lang.get("extensions", [])
                if not re.fullmatch(r"[a-z0-9_+#.-]{1,40}", lid) or not isinstance(exts, list) or len(exts) > 32:
                    raise ValueError("Language contribution is invalid.")
                clean_contrib["languages"].append({"id": lid, "extensions": [str(x)[:20] for x in exts if isinstance(x, str) and x.startswith(".")]})
            metadata = {"id": ext_id, "publisher": publisher, "name": name, "version": version,
                        "displayName": str(manifest.get("displayName", ext_id))[:120],
                        "description": str(manifest.get("description", ""))[:500],
                        "license": str(manifest.get("license", ""))[:80],
                        "enabled": True, "installed_at": time.time(), "contributes": clean_contrib,
                        "runtime": "declarative-only", "executable_code_loaded": False}
            return metadata, sanitized_assets, clean_contrib

    def install_base64(self, content_base64: str, acknowledged: bool) -> dict[str, Any]:
        if acknowledged is not True: raise PermissionError("Confirm importing this extension package.")
        if not isinstance(content_base64, str) or len(content_base64) > (MAX_EXTENSION_ARCHIVE * 4 // 3 + 16):
            raise ValueError("Extension upload exceeds its limit.")
        try: raw = base64.b64decode(content_base64, validate=True)
        except Exception: raise ValueError("Extension upload is not valid base64.") from None
        meta, assets, _ = self._parse_archive(raw)
        target = self.root / meta["id"]
        with self.lock:
            if target.exists(): raise FileExistsError("Extension is already installed; uninstall it before replacing.")
            if len([x for x in self.root.iterdir() if x.is_dir()]) >= MAX_EXTENSION_COUNT:
                raise RuntimeError("Extension installation limit reached.")
            temp = self.root / (".install-" + uuid.uuid4().hex)
            temp.mkdir(parents=True, exist_ok=False)
            try:
                for rel, data in assets.items():
                    dest = temp.joinpath(*rel.split("/"))
                    # Store only the sanitized contribution asset; paths remain within temp.
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(data)
                (temp / "cyberforge-extension.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
                os.replace(temp, target)
            except Exception:
                shutil.rmtree(temp, ignore_errors=True); raise
        return {"installed": True, "extension": meta, "notice": "Only declarative theme/snippet/language metadata was installed. Extension JavaScript, Node entrypoints and lifecycle hooks were not executed or stored."}

    def list_extensions(self, include_contributions: bool = True) -> dict[str, Any]:
        rows = []
        with self.lock:
            for folder in sorted(self.root.iterdir()):
                if not folder.is_dir() or folder.is_symlink() or folder.name.startswith("."): continue
                mf = folder / "cyberforge-extension.json"
                if mf.is_symlink() or not mf.is_file(): continue
                try:
                    meta = json.loads(mf.read_text(encoding="utf-8"))
                    if not isinstance(meta, dict) or meta.get("id") != folder.name: continue
                    row = dict(meta)
                    if not include_contributions: row.pop("contributes", None)
                    if include_contributions:
                        themes = []
                        snippets = []
                        for item in (meta.get("contributes") or {}).get("themes", []):
                            p = folder.joinpath(*self._safe_entry(item["path"]).split("/"))
                            if p.is_file() and not p.is_symlink():
                                themes.append({**item, "data": json.loads(p.read_text(encoding="utf-8"))})
                        for item in (meta.get("contributes") or {}).get("snippets", []):
                            p = folder.joinpath(*self._safe_entry(item["path"]).split("/"))
                            if p.is_file() and not p.is_symlink():
                                snippets.append({**item, "data": json.loads(p.read_text(encoding="utf-8"))})
                        row["theme_data"] = themes if row.get("enabled") else []
                        row["snippet_data"] = snippets if row.get("enabled") else []
                    rows.append(row)
                except Exception: continue
        return {"extensions": rows, "count": len(rows), "runtime": "declarative-only", "supported_contributions": ["themes", "snippets", "languages"],
                "notice": "No JavaScript extension host. Code-bearing VSIX extensions are rejected. Installed contributions are data-only."}

    def set_enabled(self, ext_id: str, enabled: bool, acknowledged: bool) -> dict[str, Any]:
        if acknowledged is not True: raise PermissionError("Confirm changing extension state.")
        folder = self._folder(ext_id); mf = folder / "cyberforge-extension.json"
        meta = json.loads(mf.read_text(encoding="utf-8")); meta["enabled"] = bool(enabled)
        temp = folder / "metadata.tmp"; temp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"); os.replace(temp, mf)
        return {"updated": True, "extension": {"id": ext_id, "enabled": bool(enabled)}}

    def uninstall(self, ext_id: str, acknowledged: bool) -> dict[str, Any]:
        if acknowledged is not True: raise PermissionError("Confirm uninstalling this extension.")
        folder = self._folder(ext_id)
        shutil.rmtree(folder)
        return {"uninstalled": True, "id": ext_id}

    def _folder(self, ext_id: str) -> Path:
        if not isinstance(ext_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}\.[a-z0-9][a-z0-9-]{1,62}", ext_id):
            raise ValueError("Extension ID is invalid.")
        folder = self.root / ext_id
        if folder.is_symlink() or not folder.is_dir(): raise FileNotFoundError("Extension is not installed.")
        return folder


class MultiDebugAdapterManager(v197_modules.DebugAdapterManager):
    """Retains Python debugpy and adds fixed, stdio DAP profiles for LLDB/.NET."""
    ADAPTERS = {
        "python-debugpy": {"label": "Python · debugpy", "language": "python", "exe": None, "args": []},
        "cpp-lldb": {"label": "C/C++ · lldb-dap", "language": "cpp", "exe": "lldb-dap", "fallback": "lldb-vscode", "args": []},
        "dotnet-netcoredbg": {"label": ".NET · netcoredbg", "language": "csharp", "exe": "netcoredbg", "args": ["--interpreter=vscode"]},
    }

    @staticmethod
    def inventory():
        rows = []
        for aid, spec in MultiDebugAdapterManager.ADAPTERS.items():
            if aid == "python-debugpy":
                available = importlib.util.find_spec("debugpy") is not None
                command = sys.executable + " -m debugpy.adapter" if available else None
            else:
                exe = shutil.which(spec["exe"]) or (shutil.which(spec.get("fallback", "")) if spec.get("fallback") else None)
                available = bool(exe); command = exe
            rows.append({"id": aid, "label": spec["label"], "language": spec["language"], "available": available, "command": command,
                         "transport": "DAP over stdio", "runs_with_host_permissions": True})
        return {"protocol": "Debug Adapter Protocol", "adapters": rows,
                "notice": "Only fixed built-in stdio profiles are supported. Adapter/debuggee processes run with OS-user permissions and require explicit approval."}

    def start_native(self, project_id: str, root: Path, adapter_id: str, program: str, source_path: str,
                     args: list[str] | None, breakpoints: list[int] | None, acknowledged: bool):
        if acknowledged is not True: raise PermissionError("Authorize starting this local debug session.")
        spec = self.ADAPTERS.get(str(adapter_id))
        if not spec or adapter_id == "python-debugpy": raise ValueError("Choose a supported native/.NET adapter.")
        root = v197_modules.safe_root(root)
        rel, path = v197_modules.safe_project_file(root, program)
        source_rel, source = v197_modules.safe_project_file(root, source_path or program)
        if adapter_id == "cpp-lldb" and path.suffix.lower() not in {".exe", ".out", ".bin", ""}:
            raise ValueError("lldb-dap expects a compiled executable, not a source file. Build the program first.")
        if adapter_id == "dotnet-netcoredbg" and path.suffix.lower() != ".dll":
            raise ValueError("netcoredbg expects a compiled .NET .dll. Build the project first.")
        executable = shutil.which(spec["exe"]) or (shutil.which(spec.get("fallback", "")) if spec.get("fallback") else None)
        if not executable: raise FileNotFoundError(f"Required adapter {spec['exe']} was not found on PATH.")
        adapter_path = Path(executable).resolve(strict=True)
        if adapter_path == root or root in adapter_path.parents: raise PermissionError("Project-local debugger adapters cannot be launched.")
        args = args or []
        if not isinstance(args, list) or len(args) > 64 or any(not isinstance(x, str) or len(x) > 1000 or "\x00" in x for x in args):
            raise ValueError("Debug arguments must be a bounded list of strings.")
        lines = sorted(set(int(x) for x in (breakpoints or [])))
        if len(lines) > 500 or any(x < 1 or x > 1_000_000 for x in lines): raise ValueError("Invalid breakpoint list.")
        with self.lock:
            self._reap()
            if len(self.sessions) >= v197_modules.MAX_DAP_SESSIONS: raise RuntimeError("DAP session limit reached.")
            if any(s["project_id"] == project_id for s in self.sessions.values()): raise RuntimeError("A debugger is already active for this project.")
            proc = subprocess.Popen([str(adapter_path), *spec["args"]], cwd=str(root), env=v197_modules.safe_child_env(),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
                close_fds=(os.name != "nt"), creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0,
                start_new_session=(os.name != "nt"))
            transport = v197_modules.FramedProcess(proc, "dap"); sid = "DAP-" + uuid.uuid4().hex[:18]
            self.sessions[sid] = {"id": sid, "project_id": project_id, "root": root, "program": rel,
                "source_path": source_rel, "adapter_id": adapter_id, "process": proc, "transport": transport}
        try:
            _, caps = transport.request("initialize", {"clientID": "cyberforge", "clientName": "CyberForge Dev Studio",
                "adapterID": "lldb" if adapter_id == "cpp-lldb" else "coreclr", "pathFormat": "path",
                "linesStartAt1": True, "columnsStartAt1": True, "supportsRunInTerminalRequest": False,
                "supportsVariableType": True, "supportsVariablePaging": True, "supportsStartDebuggingRequest": False}, timeout=15)
            launch_args = {"program": str(path), "cwd": str(root), "args": args, "stopOnEntry": True,
                           "console": "internalConsole", "runInTerminal": False, "justMyCode": True}
            launch_id, _ = transport.request("launch", launch_args, wait=False)
            if transport.wait_event("initialized", 15) is None: raise TimeoutError("DAP adapter did not send initialized event.")
            source_obj = {"name": source.name, "path": str(source)}
            _, bp = transport.request("setBreakpoints", {"source": source_obj,
                "breakpoints": [{"line": x} for x in lines], "sourceModified": False}, timeout=10)
            try: transport.request("setExceptionBreakpoints", {"filters": []}, timeout=5)
            except Exception: pass
            transport.request("configurationDone", {}, timeout=8)
            transport.wait_response(launch_id, 30)
            return {"session_id": sid, "project_id": project_id, "adapter": spec["label"], "adapter_id": adapter_id,
                "pid": proc.pid, "program": rel, "source_path": source_rel, "status": "running",
                "breakpoints": (bp or {}).get("breakpoints", []), "capabilities": caps or {},
                "notice": "Debugger and debuggee execute locally with OS-user permissions; they are not isolated by the malware sandbox."}
        except Exception:
            self.stop(sid, project_id); raise

    def command(self, sid: str, project_id: str, command: str, payload: dict[str, Any] | None, acknowledged: bool):
        if command == "setBreakpoints":
            s = self._session(sid, project_id); p = payload or {}
            rel, path = v197_modules.safe_project_file(s["root"], p.get("path", s.get("source_path", "")))
            lines = sorted(set(int(x) for x in p.get("lines", [])))
            if len(lines) > 500 or any(x < 1 or x > 1_000_000 for x in lines): raise ValueError("Invalid breakpoint list.")
            _, result = s["transport"].request("setBreakpoints", {"source": {"name": path.name, "path": str(path)},
                "breakpoints": [{"line": x} for x in lines], "sourceModified": False}, timeout=10)
            return {"session_id": sid, "command": command, "body": result or {}}
        return super().command(sid, project_id, command, payload, acknowledged)


def _safe_terminal_env() -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC", "HOME", "USERPROFILE", "USERNAME",
               "USERDOMAIN", "PSModulePath", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "LANG", "LC_ALL", "TERM"}
    env = {k: v for k, v in os.environ.items() if k in allowed and isinstance(v, str)}
    env["TERM"] = "xterm-256color"
    env["PYTHONUNBUFFERED"] = "1"
    return env


class PtyTerminalManager:
    """PTY on POSIX, ConPTY through optional pywinpty on Windows, pipe fallback."""
    def __init__(self):
        self._lock = threading.RLock(); self._sessions: dict[str, dict[str, Any]] = {}
        self._fallback = v196_modules.DeveloperTerminalManager()

    @staticmethod
    def _shell(choice: str) -> tuple[list[str], str]:
        choice = (choice or "auto").lower().strip()
        if os.name == "nt":
            choices = {"auto": ("powershell", ["-NoLogo", "-NoProfile"]),
                       "powershell": ("powershell", ["-NoLogo", "-NoProfile"]),
                       "pwsh": ("pwsh", ["-NoLogo", "-NoProfile"]), "cmd": ("cmd", ["/Q", "/D"])}
        else:
            shell = "bash" if shutil.which("bash") else "sh"
            choices = {"auto": (shell, ["--noprofile", "--norc"] if shell == "bash" else []),
                       "bash": ("bash", ["--noprofile", "--norc"]), "zsh": ("zsh", ["-f"]), "sh": ("sh", [])}
        if choice not in choices: raise ValueError("Unsupported terminal shell selection.")
        command, args = choices[choice]; executable = shutil.which(command)
        if not executable: raise FileNotFoundError(f"Shell '{command}' not found on PATH.")
        return [str(Path(executable).resolve()), *args], Path(executable).name

    def open(self, project_id: str, project_root: Path, shell: str = "auto", rows: int = 28, cols: int = 100) -> dict[str, Any]:
        root = Path(project_root).resolve(strict=True)
        if not root.is_dir() or root.is_symlink(): raise ValueError("Project terminal root is invalid.")
        argv, label = self._shell(shell)
        with self._lock:
            self._reap()
            if len(self._sessions) >= MAX_TERMINALS: raise RuntimeError("Terminal session limit reached.")
            if sum(1 for x in self._sessions.values() if x["project_id"] == project_id) >= MAX_PER_PROJECT:
                raise RuntimeError("This project already has three PTY sessions.")
            rows = max(8, min(int(rows), 120)); cols = max(30, min(int(cols), 300))
            env = _safe_terminal_env()
            if os.name == "nt":
                try:
                    from winpty import PtyProcess
                    child = PtyProcess.spawn(argv, cwd=str(root), env=env, dimensions=(rows, cols))
                    sid = "CFPTY-" + uuid.uuid4().hex[:20]
                    s = {"id": sid, "project_id": project_id, "shell": label, "cwd": str(root), "pid": child.pid,
                         "backend": "pywinpty-conpty", "child": child, "process": None, "created": time.time(),
                         "last_activity": time.time(), "chunks": deque(), "bytes": 0, "base_offset": 0, "closed": False,
                         "rows": rows, "cols": cols}
                except ImportError:
                    fallback = self._fallback.open(project_id, root, shell)
                    fallback.update({"backend": "pipe-fallback", "pty_available": False,
                                     "notice": "pywinpty is not installed. This session uses the compatible pipe fallback; install requirements-windows-pty.txt for ConPTY."})
                    return fallback
            else:
                import fcntl, pty, termios, struct
                master, slave = pty.openpty()
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                proc = subprocess.Popen(argv, cwd=str(root), env=env, stdin=slave, stdout=slave, stderr=slave,
                    bufsize=0, close_fds=True, start_new_session=True)
                os.close(slave); os.set_blocking(master, False)
                sid = "CFPTY-" + uuid.uuid4().hex[:20]
                s = {"id": sid, "project_id": project_id, "shell": label, "cwd": str(root), "pid": proc.pid,
                     "backend": "posix-pty", "master": master, "process": proc, "created": time.time(),
                     "last_activity": time.time(), "chunks": deque(), "bytes": 0, "base_offset": 0,
                     "closed": False, "rows": rows, "cols": cols}
            self._sessions[sid] = s
            thread = threading.Thread(target=self._reader, args=(sid,), daemon=True, name=f"CF-PTY-{sid[-6:]}")
            s["reader"] = thread; thread.start()
        return {"session_id": sid, "project_id": project_id, "shell": label, "cwd": str(root), "pid": s["pid"],
                "status": "running", "backend": s["backend"], "pty_available": True, "rows": rows, "cols": cols,
                "notice": "Interactive PTY/ConPTY shell. Commands run on the host with the CyberForge user's OS permissions; this is not a sandbox."}

    def _alive(self, s: dict[str, Any]) -> bool:
        if s["backend"] == "pywinpty-conpty":
            try: return bool(s["child"].isalive())
            except Exception: return False
        return s["process"].poll() is None

    def _reader(self, sid: str) -> None:
        while True:
            with self._lock:
                s = self._sessions.get(sid)
                if not s or s["closed"]: return
                backend = s["backend"]
            try:
                if backend == "pywinpty-conpty":
                    try: raw = s["child"].read(4096)
                    except EOFError: return
                    data = raw.encode("utf-8", "replace") if isinstance(raw, str) else bytes(raw)
                else:
                    import select
                    ready, _, _ = select.select([s["master"]], [], [], 0.2)
                    if not ready:
                        if not self._alive(s): return
                        continue
                    try: data = os.read(s["master"], 16_384)
                    except BlockingIOError: continue
                    except OSError: return
                    if not data: return
                with self._lock:
                    current = self._sessions.get(sid)
                    if not current or current["closed"]: return
                    current["chunks"].append(data); current["bytes"] += len(data); current["last_activity"] = time.time()
                    while current["bytes"] > MAX_OUTPUT_BYTES and current["chunks"]:
                        cut = current["chunks"].popleft(); current["bytes"] -= len(cut); current["base_offset"] += len(cut)
            except Exception:
                return

    def write(self, sid: str, project_id: str, data: str) -> dict[str, Any]:
        if sid.startswith("TERM-"):
            return self._fallback.write(sid, project_id, data)
        if not isinstance(data, str) or not data or len(data.encode("utf-8")) > MAX_INPUT_BYTES or "\x00" in data:
            raise ValueError("Terminal input must be bounded UTF-8 text without NUL.")
        with self._lock:
            s = self._get(sid, project_id)
            if not self._alive(s): raise RuntimeError("Terminal process has exited.")
            if s["backend"] == "pywinpty-conpty": s["child"].write(data)
            else: os.write(s["master"], data.encode("utf-8"))
            s["last_activity"] = time.time()
            return {"sent_bytes": len(data.encode("utf-8")), "status": "sent"}

    def _get(self, sid: str, project_id: str | None = None):
        s = self._sessions.get(sid)
        if not s or s["closed"]: raise FileNotFoundError("PTY session not found.")
        if project_id and s["project_id"] != project_id: raise PermissionError("Terminal session belongs to another project.")
        return s

    def read(self, sid: str, project_id: str | None, offset: int = 0):
        if sid.startswith("TERM-"): return self._fallback.read(sid, project_id, offset)
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0: raise ValueError("Invalid terminal offset.")
        with self._lock:
            s = self._get(sid, project_id); raw = b"".join(s["chunks"]); base = s["base_offset"]
            end = base + len(raw); start = max(base, offset) - base; data = raw[start:]
            alive = self._alive(s); s["last_activity"] = time.time()
            return {"session_id": sid, "project_id": s["project_id"], "shell": s["shell"], "cwd": s["cwd"], "pid": s["pid"],
                    "status": "running" if alive else "exited", "exit_code": None, "output": data.decode("utf-8", "replace"),
                    "offset": end, "truncated": offset < base, "base_offset": base, "backend": s["backend"], "pty_available": True}

    def interrupt(self, sid: str, project_id: str | None = None):
        if sid.startswith("TERM-"): return self._fallback.interrupt(sid, project_id)
        with self._lock:
            s = self._get(sid, project_id)
            if not self._alive(s): return {"interrupted": False, "status": "exited"}
            if s["backend"] == "pywinpty-conpty": s["child"].sendintr(); label = "CTRL_C"
            else: os.killpg(s["pid"], signal.SIGINT); label = "SIGINT"
            s["last_activity"] = time.time(); return {"interrupted": True, "session_id": sid, "signal": label}

    def resize(self, sid: str, project_id: str, rows: int, cols: int):
        if sid.startswith("TERM-"): return {"resized": False, "notice": "Pipe fallback has no terminal dimensions."}
        rows = max(8, min(int(rows), 120)); cols = max(30, min(int(cols), 300))
        with self._lock:
            s = self._get(sid, project_id)
            if s["backend"] == "pywinpty-conpty": s["child"].setwinsize(rows, cols)
            else:
                import fcntl, termios, struct
                fcntl.ioctl(s["master"], termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                try: os.killpg(s["pid"], signal.SIGWINCH)
                except ProcessLookupError: pass
            s["rows"], s["cols"] = rows, cols
        return {"resized": True, "rows": rows, "cols": cols}

    def close(self, sid: str, project_id: str | None = None):
        if sid.startswith("TERM-"): return self._fallback.close(sid, project_id)
        with self._lock:
            s = self._get(sid, project_id); s["closed"] = True; self._sessions.pop(sid, None)
        try:
            if s["backend"] == "pywinpty-conpty":
                try: s["child"].terminate(force=True)
                except Exception: pass
                try: s["child"].close(force=True)
                except Exception:
                    try: s["child"].close()
                    except Exception: pass
            else:
                # Signal the entire process group even if the shell leader has
                # already exited: a child may still be holding the PTY open.
                try: os.killpg(s["pid"], signal.SIGTERM)
                except ProcessLookupError: pass
                try: s["process"].wait(timeout=1)
                except subprocess.TimeoutExpired: pass
                # Escalate against the process group, not just the shell leader,
                # so descendants that ignored SIGTERM do not outlive the session.
                try: os.killpg(s["pid"], signal.SIGKILL)
                except ProcessLookupError: pass
                try: s["process"].wait(timeout=2)
                except subprocess.TimeoutExpired:
                    # Last-resort direct child termination; always reap it below.
                    try: s["process"].kill()
                    except OSError: pass
                    try: s["process"].wait(timeout=2)
                    except subprocess.TimeoutExpired: pass
                try: os.close(s["master"])
                except OSError: pass
        finally: return {"closed": True, "session_id": sid}

    def capabilities(self) -> dict[str, Any]:
        if os.name == "nt":
            try:
                winpty_available = importlib.util.find_spec("winpty") is not None
            except (ImportError, ValueError):
                winpty_available = False
            backend = "windows-conpty" if winpty_available else "pipe-fallback"
            pty_available = winpty_available
        else:
            backend = "posix-pty"
            pty_available = True
        asset_root = Path(__file__).resolve().parent / "static" / "vendor" / "xterm"
        xterm_ready = (asset_root / "xterm.js").is_file() and (asset_root / "addon-fit.js").is_file() and (asset_root / "xterm.css").is_file()
        return {"backend": backend, "pty_available": pty_available, "conpty_dependency": "pywinpty==3.1.2",
                "xterm_ui_available": xterm_ready, "interactive_tui": bool(pty_available and xterm_ready),
                "pipe_fallback": True, "resize": bool(pty_available), "sessions_max": MAX_TERMINALS,
                "sessions_per_project_max": MAX_PER_PROJECT,
                "permissions": "Host OS user; explicit code_execution grant; not a sandbox"}

    def list_sessions(self, project_id: str | None = None):
        with self._lock:
            rows = []
            for s in self._sessions.values():
                if not project_id or s["project_id"] == project_id:
                    rows.append({"session_id": s["id"], "project_id": s["project_id"], "shell": s["shell"], "cwd": s["cwd"],
                                 "pid": s["pid"], "status": "running" if self._alive(s) else "exited", "backend": s["backend"],
                                 "rows": s["rows"], "cols": s["cols"], "pty_available": True})
            rows.extend(self._fallback.list_sessions(project_id))
            return rows

    def _reap(self):
        now = time.time()
        stale = [sid for sid, s in self._sessions.items() if now - s["last_activity"] > SESSION_IDLE_SECONDS or not self._alive(s)]
        for sid in stale:
            try: self.close(sid)
            except Exception: pass


def ide_capabilities(dap_manager: MultiDebugAdapterManager, extension_manager: ExtensionManager,
                     terminal_manager: PtyTerminalManager) -> dict[str, Any]:
    base = v197_modules.capabilities()
    terminal = terminal_manager.capabilities()
    base.update({"version": VERSION, "dap": {**dap_manager.inventory(), "commands": sorted(v197_modules.DAP_METHODS | {"setBreakpoints"})},
                 "terminal": terminal,
                 "extensions": {"runtime": "declarative-only", "import_formats": [".vsix", ".cfext"],
                    "contributions": ["themes", "snippets", "languages"], "arbitrary_code_execution": False,
                    "installed_count": extension_manager.list_extensions(False)["count"],
                    "notice": "VSIX packages containing main/browser entrypoints, activation events, dependencies, scripts, tasks, debuggers or terminal contributions are rejected."}})
    return base
