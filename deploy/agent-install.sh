#!/usr/bin/env bash
set -euo pipefail
# Installs the read-only node agent. Run on the node being enrolled.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${EUID}" -ne 0 ]]; then echo "Run as root: sudo $0" >&2; exit 1; fi
if ! command -v systemctl >/dev/null; then echo "systemd is required." >&2; exit 1; fi
if ! id cyberforge-node >/dev/null 2>&1; then useradd --system --home-dir /var/lib/cyberforge-node --shell /usr/sbin/nologin cyberforge-node; fi
install -d -o root -g root -m 0755 /opt/cyberforge-node
install -m 0755 "$ROOT/agent/agent.py" /opt/cyberforge-node/agent.py
install -d -o root -g cyberforge-node -m 0750 /etc/cyberforge-node
if [[ ! -f /etc/cyberforge-node/agent.env ]]; then
  cat >/etc/cyberforge-node/agent.env <<'EOF'
CF_SERVER_URL=https://your-server.example
CF_NODE_ID=replace-with-node-id
CF_NODE_TOKEN=replace-with-one-time-token
CF_AGENT_INTERVAL_SECONDS=30
EOF
  chown root:cyberforge-node /etc/cyberforge-node/agent.env
  chmod 0640 /etc/cyberforge-node/agent.env
  echo "Edit /etc/cyberforge-node/agent.env with the one-time enrollment credentials, then rerun this script."
  exit 0
fi
install -m 0644 "$ROOT/agent/cyberforge-node.service" /etc/systemd/system/cyberforge-node.service
systemctl daemon-reload
systemctl enable --now cyberforge-node.service
systemctl status --no-pager cyberforge-node.service
