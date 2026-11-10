#!/usr/bin/env python3
"""Download and vendor a pinned Monaco Editor distribution for offline use.

Only package/min/vs and the upstream license are copied. Tar members are
validated and extracted manually; no archive paths are trusted.
"""
from __future__ import annotations
import argparse
import io
import shutil
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VERSION = "0.57.0"
MAX_ARCHIVE = 80 * 1024 * 1024
MAX_FILE = 12 * 1024 * 1024
MAX_TOTAL_EXTRACTED = 160 * 1024 * 1024
MAX_FILES = 6000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if not args.version.replace(".", "").isdigit() or len(args.version) > 24:
        raise SystemExit("Invalid Monaco version.")
    target = ROOT / "static" / "vendor" / "monaco" / "min" / "vs"
    monaco_root = ROOT / "static" / "vendor" / "monaco"
    if monaco_root.is_symlink() or (ROOT / "static" / "vendor").is_symlink():
        raise SystemExit("Refusing to write through a symlink in the vendor path.")
    if target.is_dir() and (target / "loader.js").is_file() and (monaco_root / "VERSION.txt").is_file() and not args.force:
        print(f"Already vendored: {target}")
        return 0
    url = f"https://registry.npmjs.org/monaco-editor/-/monaco-editor-{args.version}.tgz"
    request = urllib.request.Request(url, headers={"User-Agent": "CyberForge-Monaco-Vendor/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(MAX_ARCHIVE + 1)
    if len(raw) > MAX_ARCHIVE:
        raise SystemExit("Monaco package exceeds the 80 MiB archive safety limit.")
    staging = ROOT / "static" / "vendor" / "monaco" / ".staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    copied = 0
    extracted_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_FILES:
                raise SystemExit("Monaco archive contains too many members.")
            for member in members:
                name = PurePosixPath(member.name)
                if name.is_absolute() or ".." in name.parts or member.issym() or member.islnk():
                    continue
                rel = None
                if name.parts[:3] == ("package", "min", "vs"):
                    rel = Path(*name.parts[3:])
                    base = staging / "min" / "vs"
                elif name.parts == ("package", "LICENSE"):
                    rel = Path("LICENSE")
                    base = staging
                else:
                    continue
                if member.isdir():
                    (base / rel).mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.size < 0 or member.size > MAX_FILE:
                    continue
                extracted_bytes += member.size
                if extracted_bytes > MAX_TOTAL_EXTRACTED:
                    raise SystemExit("Monaco package exceeds the 160 MiB expanded-size safety limit.")
                source = archive.extractfile(member)
                if source is None:
                    continue
                destination = base / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source, destination.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                copied += 1
        if not (staging / "min" / "vs" / "loader.js").is_file():
            raise SystemExit("Upstream archive did not contain min/vs/loader.js.")
        if not (staging / "LICENSE").is_file():
            raise SystemExit("Upstream package license file is missing; refusing an incomplete vendor copy.")
        (staging / "VERSION.txt").write_text(args.version + "\n", encoding="ascii")
        existing = monaco_root / "min"
        if existing.exists():
            shutil.rmtree(existing)
        if (monaco_root / "LICENSE").exists():
            (monaco_root / "LICENSE").unlink()
        shutil.move(str(staging / "min"), str(monaco_root / "min"))
        shutil.move(str(staging / "LICENSE"), str(monaco_root / "LICENSE")) if (staging / "LICENSE").exists() else None
        (monaco_root / "VERSION.txt").write_text(args.version + "\n", encoding="ascii")
        print(f"Vendored Monaco {args.version}: {copied} files -> {existing / 'vs'}")
        return 0
    finally:
        shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
