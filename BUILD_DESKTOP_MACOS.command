#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pip install -r requirements-build-macos.txt
python3 build_desktop.py --platform macos "$@"
