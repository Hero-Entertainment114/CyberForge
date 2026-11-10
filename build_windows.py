#!/usr/bin/env python3
"""Backward-compatible Windows-only entry point for the native desktop builder."""
import sys
from build_desktop import main

if __name__ == "__main__":
    if sys.platform != "win32":
        raise SystemExit("Windows builds must run on Windows. Use build_desktop.py on the current OS.")
    raise SystemExit(main(["--platform", "windows", *sys.argv[1:]]))
