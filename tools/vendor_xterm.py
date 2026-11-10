#!/usr/bin/env python3
"""Download pinned xterm.js browser assets for the integrated PTY terminal.

Only fetches public, fixed jsDelivr package URLs. No project files or user data
are uploaded. Run explicitly with network access to enable a fully local xterm UI.
"""
from __future__ import annotations
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "static" / "vendor" / "xterm"
ASSETS = {
    "xterm.js": "https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/lib/xterm.js",
    "xterm.css": "https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/css/xterm.css",
    "addon-fit.js": "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.11.0/lib/addon-fit.js",
    "LICENSE-xterm.txt": "https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/LICENSE",
    "LICENSE-addon-fit.txt": "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.11.0/LICENSE",
}

def fetch(name: str, url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "CyberForge-VendorTool/1.9.9.1"})
    with urllib.request.urlopen(req, timeout=25) as response:
        data = response.read(12 * 1024 * 1024 + 1)
    if not data or len(data) > 12 * 1024 * 1024:
        raise RuntimeError(f"Unexpected asset size: {name}")
    if name.endswith(".js") and (b"sourceMappingURL" in data[-500:] or len(data) < 10_000):
        # Source map comments are harmless, but tiny error pages are not assets.
        if len(data) < 10_000: raise RuntimeError(f"CDN did not return a JavaScript bundle: {name}")
    return data

def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, url in ASSETS.items():
        data = fetch(name, url)
        (OUT / name).write_bytes(data)
        results[name] = {"url": url, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    manifest = {"name": "CyberForge vendored xterm assets", "xterm": "6.0.0", "addon_fit": "0.11.0",
                "license": "MIT", "assets": results, "generated_by": "tools/vendor_xterm.py"}
    (OUT / "VENDOR_MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"installed": True, "directory": str(OUT), "assets": results}, indent=2))
    return 0

if __name__ == "__main__":
    try: raise SystemExit(main())
    except Exception as exc:
        print(f"xterm vendor failed: {exc}", file=sys.stderr); raise SystemExit(1)
