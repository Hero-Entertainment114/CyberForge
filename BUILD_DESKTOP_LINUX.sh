#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pip install -r requirements-build-linux.txt
python3 build_desktop.py --platform linux "${@}"
