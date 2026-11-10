#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then echo "Usage: $0 https://github.com/OWNER/CyberForge-AIO.git" >&2; exit 2; fi
REMOTE="$1"
git init -b main
git add .
git diff --cached --quiet && { echo 'Nothing to commit'; exit 1; }
git commit -m "Publish CyberForge AIO v1.9.9.1"
git remote add origin "$REMOTE"
git push -u origin main
