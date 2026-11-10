#!/usr/bin/env python3
"""Minimal CyberForge Linux node agent. Read-only telemetry; no remote command channel."""
from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def _meminfo():
    out = {}
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            k, _, rest = line.partition(':')
            p = rest.split()
            if p and p[0].isdigit():
                out[k] = int(p[0]) * (1024 if len(p) > 1 and p[1] == 'kB' else 1)
    except OSError:
        pass
    return out


def collect():
    mem = _meminfo()
    disk = shutil.disk_usage('/')
    try:
        load = list(os.getloadavg())
    except (AttributeError, OSError):
        load = []
    services = {}
    # Read-only allowlist only. No caller-provided service name or command is accepted.
    systemctl = shutil.which('systemctl')
    if systemctl and Path('/run/systemd/system').exists():
        import subprocess
        for name in ('ssh', 'sshd', 'nginx', 'apache2', 'httpd', 'docker', 'containerd', 'postgresql', 'redis-server', 'ollama', 'prometheus'):
            try:
                cp = subprocess.run([systemctl, 'is-active', name], capture_output=True, text=True,
                                    timeout=2, check=False, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
                services[name] = (cp.stdout.strip() or cp.stderr.strip() or 'unknown')[:40]
            except (OSError, subprocess.TimeoutExpired):
                services[name] = 'unknown'
    os_release = {}
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            k, sep, v = line.partition('=')
            if sep and k in ('PRETTY_NAME', 'ID', 'VERSION_ID'):
                os_release[k] = v.strip().strip('"')[:120]
    except OSError:
        pass
    cpu_model = 'Unknown'
    try:
        for line in Path('/proc/cpuinfo').read_text(errors='replace').splitlines():
            if line.lower().startswith(('model name', 'hardware')):
                cpu_model = line.split(':', 1)[-1].strip()[:160]
                break
    except OSError:
        pass
    return {
        'hostname': platform.node()[:180], 'platform': platform.system(), 'kernel': platform.release()[:180],
        'architecture': platform.machine()[:80], 'os_release': os_release, 'cpu_model': cpu_model,
        'cpu_logical_cores': os.cpu_count() or 1, 'load_average': load,
        'memory_total_bytes': mem.get('MemTotal', 0), 'memory_available_bytes': mem.get('MemAvailable', 0),
        'disk_total_bytes': disk.total, 'disk_free_bytes': disk.free,
        'gpu_tooling': {'nvidia_smi': bool(shutil.which('nvidia-smi')), 'rocm_smi': bool(shutil.which('rocm-smi')),
                        'xpu_smi': bool(shutil.which('xpu-smi'))},
        'services': services, 'python': platform.python_version(),
        'collected_at': datetime.now(timezone.utc).isoformat(timespec='seconds')
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_report():
    if platform.system() != 'Linux':
        raise SystemExit('CyberForge node agent v2.1.0 supports Linux only')
    server = os.getenv('CF_SERVER_URL', '').rstrip('/')
    node_id = os.getenv('CF_NODE_ID', '')
    token = os.getenv('CF_NODE_TOKEN', '')
    if not server or not node_id or not token:
        raise SystemExit('CF_SERVER_URL, CF_NODE_ID and CF_NODE_TOKEN must be configured')
    parsed = urllib.parse.urlsplit(server)
    if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit('CF_SERVER_URL must be a valid HTTP(S) origin')
    if parsed.scheme != 'https' and parsed.hostname not in ('127.0.0.1', 'localhost', '::1'):
        raise SystemExit('Remote node reporting requires HTTPS; HTTP is allowed only for loopback testing')
    payload = json.dumps(collect(), separators=(',', ':')).encode()
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(18)
    url = server + '/api/v200/nodes/report'
    req = urllib.request.Request(url, data=payload, method='POST', headers={
        'Content-Type': 'application/json', 'X-CF-Node-ID': node_id, 'X-CF-Node-Token': token,
        'X-CF-Timestamp': timestamp, 'X-CF-Nonce': nonce,
        'User-Agent': 'CyberForge-Node-Agent/2.1.0'
    })
    # Do not forward node credentials or telemetry to a redirected host.
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(req, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError(f'Unexpected server status: {response.status}')
        return json.loads(response.read(65536).decode())


def main():
    interval = max(15, min(3600, int(os.getenv('CF_AGENT_INTERVAL_SECONDS', '30'))))
    once = os.getenv('CF_AGENT_ONCE', '0') == '1'
    while True:
        try:
            result = send_report()
            print(json.dumps({'ok': True, 'received_at': result.get('received_at')}), flush=True)
        except Exception as exc:
            # Avoid leaking credentials; error text is only the transport/runtime message.
            print(json.dumps({'ok': False, 'error': str(exc)[:240]}), file=sys.stderr, flush=True)
        if once:
            return
        time.sleep(interval)


if __name__ == '__main__':
    main()
