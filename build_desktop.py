#!/usr/bin/env python3
"""Build CyberForge native desktop bundles on the current host OS.

PyInstaller is intentionally invoked only for the current platform. It is not a
cross-compiler; CI runs this script on Windows, macOS, and Linux separately.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent
VERSION = (ROOT / "VERSION.txt").read_text(encoding="utf-8").strip()
LABELS = {
    "aio": "CyberForge-AIO",
    "dev": "CyberForge-Dev",
    "security": "CyberForge-Security",
}
PLATFORM_ALIASES = {
    "win32": "windows",
    "cygwin": "windows",
    "darwin": "macos",
    "linux": "linux",
}


def current_platform() -> str:
    try:
        return PLATFORM_ALIASES[sys.platform]
    except KeyError as exc:
        raise SystemExit(f"Unsupported build platform: {sys.platform}") from exc


def resolve_edition(requested: str | None) -> str:
    if requested:
        edition = requested
    else:
        try:
            edition = json.loads((ROOT / "edition.json").read_text(encoding="utf-8")).get("edition", "aio")
        except (OSError, json.JSONDecodeError, AttributeError):
            edition = "aio"
    if edition not in LABELS:
        raise SystemExit(f"Invalid edition: {edition!r}. Choose aio, dev, or security.")
    return edition


def pyinstaller_command(edition: str, target: str, *, clean: bool = True) -> tuple[list[str], Path]:
    if target not in {"windows", "macos", "linux"}:
        raise ValueError(f"Unsupported target: {target}")
    sep = ";" if target == "windows" else ":"
    name = LABELS[edition]
    staging = ROOT / "build" / f"desktop-{target}-{edition}"
    staging.mkdir(parents=True, exist_ok=True)
    staged_manifest = staging / "edition.json"
    staged_manifest.write_text(json.dumps({"edition": edition}, indent=2) + "\n", encoding="utf-8")

    work = staging / "work"
    spec = staging / "spec"
    dist = ROOT / "dist"
    icon_file = ROOT / "assets" / {"windows": "cyberforge.ico", "macos": "cyberforge.icns", "linux": "cyberforge.png"}[target]
    if not icon_file.is_file():
        raise FileNotFoundError(f"Native app icon is missing: {icon_file}")
    command = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--windowed",
        "--onedir",
        "--name", name,
        "--distpath", str(dist),
        "--workpath", str(work),
        "--specpath", str(spec),
        "--add-data", f"static{sep}static",
        "--add-data", f"locales{sep}locales",
        "--add-data", f"plugins{sep}plugins",
        "--add-data", f"{staged_manifest}{sep}.",
        "--collect-all", "webview",
        "--collect-all", "cryptography",
        "--collect-all", "psutil",
    ]
    if clean:
        command.append("--clean")
    if target in {"windows", "macos"}:
        command += ["--icon", str(icon_file)]

    if target == "windows":
        command += [
            "--collect-all", "clr_loader",
            "--collect-all", "pythonnet",
            "--hidden-import", "clr",
            "--hidden-import", "webview.platforms.winforms",
            "--hidden-import", "webview.platforms.edgechromium",
        ]
    elif target == "macos":
        command += [
            "--hidden-import", "webview.platforms.cocoa",
            "--collect-all", "objc",
        ]
        command += ["--osx-bundle-identifier", "org.cyberforge.desktop"]
    else:
        command += [
            "--hidden-import", "webview.platforms.qt",
            "--collect-all", "PySide6",
            "--collect-all", "shiboken6",
        ]

    command.append("desktop_entry.py")
    return command, dist


def expected_artifact(name: str, target: str, dist: Path) -> Path:
    if target == "macos":
        return dist / f"{name}.app"
    return dist / name


def smoke_test(artifact: Path, name: str, target: str) -> None:
    if target == "macos":
        executable = artifact / "Contents" / "MacOS" / name
    elif target == "windows":
        executable = artifact / f"{name}.exe"
    else:
        executable = artifact / name
    if not executable.is_file():
        raise RuntimeError(f"Packaged executable not found: {executable}")
    if target != "windows":
        executable.chmod(executable.stat().st_mode | 0o111)
    env = os.environ.copy()
    if target == "linux":
        # A no-display smoke test must not require an X11 session.
        env.setdefault("QT_QPA_PLATFORM", "offscreen")
    result = subprocess.run(
        [str(executable), "--self-test"],
        cwd=str(ROOT), env=env, check=False, timeout=45,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if result.returncode:
        detail = (result.stdout + "\n" + result.stderr).strip()[-5000:]
        raise RuntimeError(f"Packaged self-test failed ({result.returncode}):\n{detail}")


def write_bundle_readme(artifact: Path, target: str, edition: str, name: str) -> None:
    text = f"""CyberForge {name} v{VERSION}\n\n""" + {
        "windows": (
            "Start by double-clicking " + name + ".exe.\n"
            "Requires the Microsoft Edge WebView2 Runtime and a compatible .NET runtime for pythonnet "
            "(prefer .NET 6+ Desktop Runtime; .NET Framework 4.6.2 is the fallback on supported architectures). "
            "If the native window cannot start, CyberForge attempts to open the local interface in your default browser.\n"
            "User data is stored under %LOCALAPPDATA%\\CyberForgeAIO*.\n"
        ),
        "macos": (
            f"Open {name}.app. If macOS blocks the app, verify its origin before allowing it.\n"
            "The app uses the macOS WebKit web view. User data is stored under ~/Library/Application Support.\n"
            "This build is not code-signed or notarized.\n"
        ),
        "linux": (
            f"Run ./{name}. The host needs a compatible Qt6 WebEngine / desktop runtime.\n"
            "User data is stored under $XDG_DATA_HOME or ~/.local/share.\n"
            "Builds are tied to the glibc baseline of the build runner; build on the oldest Linux release you support.\n"
        ),
    }[target]
    text += "\nThe bundle is portable as a folder/app bundle. Keep all bundled files together.\n"
    if target == "macos":
        readme_path = artifact / "Contents" / "Resources" / "CYBERFORGE_DESKTOP_README.txt"
        readme_path.parent.mkdir(parents=True, exist_ok=True)
    elif artifact.is_dir():
        readme_path = artifact / "CYBERFORGE_DESKTOP_README.txt"
    else:
        readme_path = artifact.parent / "CYBERFORGE_DESKTOP_README.txt"
    readme_path.write_text(text, encoding="utf-8")
    if target == "linux":
        shutil.copy2(ROOT / "assets" / "cyberforge.png", artifact / "cyberforge.png")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a native CyberForge desktop bundle for this operating system.")
    parser.add_argument("--edition", choices=tuple(LABELS), default=None)
    parser.add_argument("--platform", choices=("windows", "macos", "linux"), default=None,
                        help="Must match the current host OS; cross-compilation is not supported.")
    parser.add_argument("--no-clean", action="store_true", help="Reuse PyInstaller work files.")
    parser.add_argument("--dry-run", action="store_true", help="Print the build command without invoking PyInstaller.")
    args = parser.parse_args(argv)

    host = current_platform()
    if args.platform and args.platform != host:
        raise SystemExit(f"Refusing cross-build: host is {host}, requested target is {args.platform}. Run on the target OS.")
    target = host
    edition = resolve_edition(args.edition)
    name = LABELS[edition]
    command, dist = pyinstaller_command(edition, target, clean=not args.no_clean)
    print(f"CyberForge v{VERSION} | edition={edition} | platform={target} | arch={platform.machine()}")
    print("Building native desktop bundle with PyInstaller (onedir).")
    if args.dry_run:
        print(subprocess.list2cmdline(command) if target == "windows" else " ".join(command))
        return 0

    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode:
        print("Build failed. Review the PyInstaller output above.", file=sys.stderr)
        return result.returncode

    artifact = expected_artifact(name, target, dist)
    if not artifact.exists():
        print(f"Build output was not found: {artifact}", file=sys.stderr)
        return 2
    try:
        smoke_test(artifact, name, target)
        write_bundle_readme(artifact, target, edition, name)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"Bundle verification failed: {exc}", file=sys.stderr)
        return 3

    print(f"BUILD + SMOKE TEST SUCCESS: {artifact}")
    print("Distribute the entire folder/app bundle, not only the executable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
