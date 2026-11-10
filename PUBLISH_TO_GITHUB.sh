#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then echo "Usage: $0 https://github.com/OWNER/CyberForge-Server.git" >&2; exit 2; fi
if [[ ! -f LICENSE ]]; then echo 'Add the project LICENSE before publishing this repository as open source.' >&2; exit 3; fi
REMOTE="$1"
git init -b main
git add .
git diff --cached --quiet && { echo 'Nothing to commit'; exit 1; }
git commit -m "Publish CyberForge Server Edition v2.1.0 Official Stable"
git remote add origin "$REMOTE"
git push -u origin main
