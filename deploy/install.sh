#!/usr/bin/env bash
set -Eeuo pipefail

# Transactional installer/upgrader for CyberForge Server Edition.
# Application code is staged in a versioned release directory; persistent data
# and secrets stay outside it. The active `current` symlink is switched only
# after a verified backup and schema preflight.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="/opt/cyberforge-server"
RELEASES_DIR="$APP_ROOT/releases"
CURRENT="$APP_ROOT/current"
DATA_DIR="/var/lib/cyberforge-server"
ETC_DIR="/etc/cyberforge-server"
BACKUP_DIR="/var/backups/cyberforge-server"
UNIT="/etc/systemd/system/cyberforge-server.service"
TAIL_UNIT="/etc/systemd/system/cyberforge-security-tail@.service"
LOCK_FILE="/run/lock/cyberforge-server-install.lock"
STAGE=""
OLD_TARGET=""
OLD_UNIT_BACKUP=""
UNIT_WAS_PRESENT=0
SWITCHED=0
SERVICE_WAS_ACTIVE=0
SERVICE_ENABLED_STATE=""

say() { printf '[CyberForge installer] %s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }

rollback() {
  local rc=$?
  trap - ERR
  if [[ "$SWITCHED" == "1" ]]; then
    say "Upgrade failed; rolling back the active release."
    systemctl stop cyberforge-server.service >/dev/null 2>&1 || true
    if [[ -n "$OLD_TARGET" ]]; then
      ln -sfn "$OLD_TARGET" "$APP_ROOT/current.rollback"
      mv -Tf "$APP_ROOT/current.rollback" "$CURRENT"
    else
      rm -f "$CURRENT"
    fi
    if [[ "$UNIT_WAS_PRESENT" == "1" && -n "$OLD_UNIT_BACKUP" && -f "$OLD_UNIT_BACKUP" ]]; then
      install -m 0644 "$OLD_UNIT_BACKUP" "$UNIT"
    else
      rm -f "$UNIT"
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    case "$SERVICE_ENABLED_STATE" in
      enabled) systemctl enable cyberforge-server.service >/dev/null 2>&1 || true ;;
      enabled-runtime) systemctl enable --runtime cyberforge-server.service >/dev/null 2>&1 || true ;;
      *) systemctl disable cyberforge-server.service >/dev/null 2>&1 || true ;;
    esac
    if [[ "$SERVICE_WAS_ACTIVE" == "1" ]]; then
      systemctl start cyberforge-server.service >/dev/null 2>&1 || true
    fi
  elif [[ "$SERVICE_WAS_ACTIVE" == "1" ]]; then
    # Failure before the symlink swap: the old unit/code are untouched.
    systemctl start cyberforge-server.service >/dev/null 2>&1 || true
  fi
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then rm -rf -- "$STAGE"; fi
  exit "$rc"
}
trap rollback ERR

[[ "$EUID" -eq 0 ]] || die "Run as root: sudo $0"
[[ "$(uname -s)" == "Linux" ]] || die "Server Edition supports Linux only."
command -v systemctl >/dev/null || die "systemd is required."
command -v python3 >/dev/null || die "python3 is required."
command -v flock >/dev/null || die "flock is required."
command -v runuser >/dev/null || die "runuser is required."
[[ -f "$ROOT/server.py" && -f "$ROOT/VERSION.txt" && -f "$ROOT/.env.example" ]] || die "Run this script from an extracted CyberForge source release."

python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10+ is required")
PY
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION.txt")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION.txt is not a valid release version."
python3 - "$ROOT/edition.json" "$VERSION" <<'PY'
import json, sys
from pathlib import Path
obj=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
if obj.get('version') != sys.argv[2] or obj.get('edition') != 'server-linux':
    raise SystemExit('edition.json does not match this Linux Server release')
PY

install -d -m 0755 /run/lock
exec 9>"$LOCK_FILE"
flock -n 9 || die "Another CyberForge install/upgrade is running."

if ! getent passwd cyberforge-server >/dev/null; then
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin cyberforge-server
fi
install -d -o root -g root -m 0755 "$APP_ROOT" "$RELEASES_DIR"
install -d -o cyberforge-server -g cyberforge-server -m 0700 "$DATA_DIR"
install -d -o root -g cyberforge-server -m 0750 "$ETC_DIR" "$ETC_DIR/telemetry"
install -d -o cyberforge-server -g cyberforge-server -m 0700 "$BACKUP_DIR"

if [[ ! -f "$ETC_DIR/server.env" ]]; then
  install -m 0640 -o root -g cyberforge-server "$ROOT/.env.example" "$ETC_DIR/server.env"
  say "Created $ETC_DIR/server.env from the example; review it before exposing the service."
fi
chown root:cyberforge-server "$ETC_DIR/server.env"
chmod 0640 "$ETC_DIR/server.env"

# Parse only simple KEY=VALUE lines; never eval or source an operator-controlled file.
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
  [[ "$line" == *=* ]] || continue
  key="${line%%=*}"; value="${line#*=}"
  key="${key//[[:space:]]/}"
  [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || continue
  if [[ "$value" == \"*\" && "$value" == *\" ]]; then value="${value:1:${#value}-2}";
  elif [[ "$value" == \'*\' && "$value" == *\' ]]; then value="${value:1:${#value}-2}"; fi
  export "$key=$value"
done < "$ETC_DIR/server.env"

if [[ "${CF_STORAGE_BACKEND:-sqlite}" != "sqlite" && "${CF_STORAGE_BACKEND:-sqlite}" != "postgres" ]]; then
  die "CF_STORAGE_BACKEND must be sqlite or postgres."
fi
if [[ "${CF_STORAGE_BACKEND:-sqlite}" == "postgres" ]]; then
  [[ -n "${CF_DATABASE_URL:-}" && -n "${CF_DISTRIBUTED_DATA_KEY:-}" ]] || die "PostgreSQL mode requires CF_DATABASE_URL and CF_DISTRIBUTED_DATA_KEY."
fi
if [[ -n "${CF_REDIS_URL:-}" && "${CF_STORAGE_BACKEND:-sqlite}" != "postgres" ]]; then
  say "Redis may be used for optional coordination, but PostgreSQL remains the required shared durable store for multi-replica mode."
fi

RELEASE_DIR="$RELEASES_DIR/$VERSION"
[[ ! -e "$RELEASE_DIR" ]] || RELEASE_DIR="$RELEASES_DIR/${VERSION}-$(date -u +%Y%m%dT%H%M%SZ)"
STAGE="$(mktemp -d "$RELEASES_DIR/.staging-${VERSION}.XXXXXX")"
cp -a "$ROOT/." "$STAGE/"
rm -rf "$STAGE/data" "$STAGE/__pycache__"
find "$STAGE" -type d -name __pycache__ -prune -exec rm -rf {} +
python3 -m venv "$STAGE/.venv"
if [[ "${CF_STORAGE_BACKEND:-sqlite}" == "postgres" || -n "${CF_REDIS_URL:-}" ]]; then
  say "Installing optional distributed storage drivers into the staged virtual environment."
  "$STAGE/.venv/bin/python" -m pip install --no-input --no-cache-dir --disable-pip-version-check -r "$STAGE/requirements-distributed.txt"
fi
chown -R root:root "$STAGE"
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod go-w {} +

# Remember the old release and unit so an unsuccessful health-check can roll back.
if [[ -L "$CURRENT" ]]; then OLD_TARGET="$(readlink -f "$CURRENT")"; fi
if [[ -f "$UNIT" ]]; then
  UNIT_WAS_PRESENT=1
  OLD_UNIT_BACKUP="$BACKUP_DIR/cyberforge-server.service.pre-${VERSION}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  cp -a "$UNIT" "$OLD_UNIT_BACKUP"
  chmod 0600 "$OLD_UNIT_BACKUP"
fi
if systemctl is-active --quiet cyberforge-server.service; then SERVICE_WAS_ACTIVE=1; fi
SERVICE_ENABLED_STATE="$(systemctl is-enabled cyberforge-server.service 2>/dev/null || true)"

say "Stopping the service before schema preflight and data backup."
systemctl stop cyberforge-server.service >/dev/null 2>&1 || true

DB_PATH="$DATA_DIR/server.sqlite3"
if [[ "${CF_STORAGE_BACKEND:-sqlite}" == "postgres" ]]; then
  BACKUP_EXT="dump"
  SHOULD_BACKUP=1
else
  BACKUP_EXT="sqlite3"
  SHOULD_BACKUP=0
  [[ -s "$DB_PATH" ]] && SHOULD_BACKUP=1
fi
if [[ "$SHOULD_BACKUP" == "1" ]]; then
  BACKUP_PATH="$BACKUP_DIR/pre-${VERSION}-$(date -u +%Y%m%dT%H%M%SZ)-$$.$BACKUP_EXT"
  say "Creating and verifying a database backup before upgrade."
  runuser -u cyberforge-server -- env CF_SERVER_DATA_DIR="$DATA_DIR" CF_STORAGE_BACKEND="${CF_STORAGE_BACKEND:-sqlite}" CF_DATABASE_URL="${CF_DATABASE_URL:-}" CF_DISTRIBUTED_DATA_KEY="${CF_DISTRIBUTED_DATA_KEY:-}" \
    "$STAGE/.venv/bin/python" "$STAGE/server.py" --data-dir "$DATA_DIR" backup --output "$BACKUP_PATH" > "$BACKUP_DIR/last-backup-result.json"
  chown cyberforge-server:cyberforge-server "$BACKUP_PATH" "$BACKUP_DIR/last-backup-result.json"
  chmod 0600 "$BACKUP_PATH" "$BACKUP_DIR/last-backup-result.json"
  runuser -u cyberforge-server -- env CF_SERVER_DATA_DIR="$DATA_DIR" CF_STORAGE_BACKEND="${CF_STORAGE_BACKEND:-sqlite}" CF_DATABASE_URL="${CF_DATABASE_URL:-}" \
    "$STAGE/.venv/bin/python" "$STAGE/server.py" --data-dir "$DATA_DIR" verify-backup --path "$BACKUP_PATH" | grep -q '"valid": true'
else
  say "No existing database found; initial-install bootstrap will create it."
fi

say "Running additive schema and audit preflight using the staged release."
runuser -u cyberforge-server -- env CF_SERVER_DATA_DIR="$DATA_DIR" CF_STORAGE_BACKEND="${CF_STORAGE_BACKEND:-sqlite}" CF_DATABASE_URL="${CF_DATABASE_URL:-}" CF_DISTRIBUTED_DATA_KEY="${CF_DISTRIBUTED_DATA_KEY:-}" \
  "$STAGE/.venv/bin/python" "$STAGE/server.py" --data-dir "$DATA_DIR" preflight > "$BACKUP_DIR/preflight-${VERSION}.json"
chown cyberforge-server:cyberforge-server "$BACKUP_DIR/preflight-${VERSION}.json"
chmod 0600 "$BACKUP_DIR/preflight-${VERSION}.json"

mv "$STAGE" "$RELEASE_DIR"
STAGE=""
chown -R root:root "$RELEASE_DIR"
ln -sfn "$RELEASE_DIR" "$APP_ROOT/current.new"
mv -Tf "$APP_ROOT/current.new" "$CURRENT"
SWITCHED=1

install -m 0644 "$CURRENT/deploy/systemd/cyberforge-server.service" "$UNIT"
install -m 0644 "$CURRENT/deploy/systemd/cyberforge-security-tail@.service.example" "$TAIL_UNIT"
systemctl daemon-reload

TOKEN_COUNT="$(runuser -u cyberforge-server -- env CF_SERVER_DATA_DIR="$DATA_DIR" CF_STORAGE_BACKEND="${CF_STORAGE_BACKEND:-sqlite}" CF_DATABASE_URL="${CF_DATABASE_URL:-}" \
  "$CURRENT/.venv/bin/python" "$CURRENT/server.py" --data-dir "$DATA_DIR" token-count)"
if [[ "$TOKEN_COUNT" == "0" ]]; then
  say "Creating the initial administrator token (shown exactly once):"
  runuser -u cyberforge-server -- env CF_SERVER_DATA_DIR="$DATA_DIR" CF_STORAGE_BACKEND="${CF_STORAGE_BACKEND:-sqlite}" CF_DATABASE_URL="${CF_DATABASE_URL:-}" \
    "$CURRENT/.venv/bin/python" "$CURRENT/server.py" --data-dir "$DATA_DIR" init-admin
fi

systemctl enable cyberforge-server.service
systemctl start cyberforge-server.service
HEALTH_OK=0
for _ in $(seq 1 30); do
  if "$CURRENT/.venv/bin/python" - <<'PY'
import json, urllib.request
with urllib.request.urlopen('http://127.0.0.1:8787/api/v200/health', timeout=2) as r:
    data=json.loads(r.read(65536))
    raise SystemExit(0 if r.status == 200 and data.get('ok') else 1)
PY
  then HEALTH_OK=1; break; fi
  sleep 1
done
[[ "$HEALTH_OK" == "1" ]] || { say "The service did not pass its local health check."; false; }

SWITCHED=0
say "CyberForge Server Edition $VERSION installed successfully."
say "Active release: $RELEASE_DIR"
say "Data: $DATA_DIR"
say "Local URL: http://127.0.0.1:8787"
say "A previous release, if any, is retained under $RELEASES_DIR for manual recovery."
say "Configure Caddy/Nginx TLS before remote access."
say "Check: systemctl status cyberforge-server"
trap - ERR
