"""CyberForge v1.9.5 runtime diagnostics, bounded PCAP decoding and approved defensive agent workflows.

No packet payloads, HTTP query values, credentials, TLS secrets or certificate bodies are
returned. Packet decoding is metadata-only and works offline. Docker probes run only when
explicitly requested and use an existing CyberForge image with no sample mounted.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

VERSION = "1.9.5"
MAX_PCAP_BYTES = 2 * 1024 * 1024
MAX_PACKETS = 12000
MAX_DECODE_EVENTS = 5000
MAX_TCP_STREAMS = 256
MAX_STREAM_BYTES = 65536
MAX_DOCKER_OUTPUT = 6000


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: Any, limit: int = 300) -> str:
    text = str(value or "")
    text = re.sub(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)\S+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(api[_-]?key|token|secret|password)=([^\s&]+)", r"\1=[REDACTED]", text)
    text = re.sub(r"\b(?:sk-|gsk_|gh[pousr]_)[A-Za-z0-9_-]{12,}\b", "[REDACTED_KEY]", text)
    return text[:limit]


def _run_command(args: list[str], timeout: int = 8) -> dict[str, Any]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False,
                           shell=False, encoding="utf-8", errors="replace")
        return {"returncode": p.returncode, "stdout": (p.stdout or "")[-MAX_DOCKER_OUTPUT:],
                "stderr": (p.stderr or "")[-MAX_DOCKER_OUTPUT:], "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "Command timed out.", "timed_out": True}
    except Exception as exc:
        return {"returncode": None, "stdout": "", "stderr": type(exc).__name__, "timed_out": False}


def docker_desktop_diagnostics() -> dict[str, Any]:
    """Read-only diagnostics for Docker Desktop/Engine. Never changes host settings."""
    host = platform.system()
    docker = shutil.which("docker")
    result: dict[str, Any] = {
        "schema": "cyberforge.docker-diagnostics.v1", "checked_at": _utc(),
        "host_platform": host, "docker_cli": docker or None, "daemon_reachable": False,
        "linux_container_engine": None, "checks": [],
        "notice": "Read-only checks only. No images are pulled, no containers started and no system settings changed.",
    }
    if not docker:
        result["checks"].append({"name": "docker_cli", "ok": False, "detail": "Docker CLI not found on PATH."})
        result["limitations"] = ["Install/start Docker Desktop or Docker Engine, then reopen CyberForge."]
        return result

    version = _run_command([docker, "version", "--format", "{{json .}}"], 8)
    info = _run_command([docker, "info", "--format", "{{json .}}"], 10)
    context = _run_command([docker, "context", "show"], 5)
    info_obj: dict[str, Any] = {}
    version_obj: dict[str, Any] = {}
    try:
        raw = json.loads(info.get("stdout") or "{}")
        if isinstance(raw, dict): info_obj = raw
    except Exception: pass
    try:
        raw = json.loads(version.get("stdout") or "{}")
        if isinstance(raw, dict): version_obj = raw
    except Exception: pass
    server = version_obj.get("Server") if isinstance(version_obj.get("Server"), dict) else {}
    client = version_obj.get("Client") if isinstance(version_obj.get("Client"), dict) else {}
    reachable = info.get("returncode") == 0 and bool(info_obj)
    os_type = str(info_obj.get("OSType", "")).lower()
    result.update({
        "daemon_reachable": reachable,
        "linux_container_engine": (os_type == "linux") if reachable else None,
        "engine": {"server_version": server.get("Version"), "client_version": client.get("Version"),
                   "os_type": os_type or None, "operating_system": _safe_text(info_obj.get("OperatingSystem", ""), 180),
                   "architecture": info_obj.get("Architecture"), "kernel_version": _safe_text(info_obj.get("KernelVersion", ""), 160),
                   "security_options": info_obj.get("SecurityOptions", []), "driver": info_obj.get("Driver")},
        "context": _safe_text(context.get("stdout", "").strip(), 120) if context.get("returncode") == 0 else None,
    })
    result["checks"].extend([
        {"name": "docker_cli", "ok": True, "detail": docker},
        {"name": "docker_daemon", "ok": reachable, "detail": "Docker daemon is reachable." if reachable else _safe_text(info.get("stderr") or version.get("stderr") or "Docker daemon unavailable.", 500)},
        {"name": "linux_container_mode", "ok": os_type == "linux" if reachable else False,
         "detail": "Linux containers detected." if os_type == "linux" else ("Windows container engine detected; NetLab requires Linux containers." if reachable else "Not verified.")},
    ])
    if host == "Windows":
        wsl = shutil.which("wsl.exe") or shutil.which("wsl")
        if wsl:
            for name, args in (("wsl_version", [wsl, "--version"]), ("wsl_status", [wsl, "--status"]), ("wsl_distributions", [wsl, "-l", "-v"])):
                probe = _run_command(args, 8)
                result["checks"].append({"name": name, "ok": probe.get("returncode") == 0,
                                         "detail": _safe_text(probe.get("stdout") or probe.get("stderr"), 1800)})
        else:
            result["checks"].append({"name": "wsl", "ok": False, "detail": "wsl.exe was not found."})
        ps = shutil.which("powershell.exe") or shutil.which("powershell")
        if ps:
            proc = _run_command([ps, "-NoProfile", "-NonInteractive", "-Command",
                                 "Get-Process -Name 'Docker Desktop','com.docker.backend' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName"], 6)
            result["checks"].append({"name": "docker_desktop_process", "ok": proc.get("returncode") == 0 and bool(proc.get("stdout", "").strip()),
                                     "detail": _safe_text(proc.get("stdout") or "Docker Desktop process not detected.", 500)})
        result["windows_notes"] = [
            "Docker Desktop Linux containers run inside its managed Linux VM/WSL2 or Hyper-V backend; the Linux loopback PCAP is captured inside the container namespace, not from the Windows host NIC.",
            "WSL2 and Hyper-V backends expose different host visibility. Do not infer that a Windows host packet capture represents the container loopback interface.",
            "Docker Desktop's daemon reachability does not prove NET_RAW is granted; run the explicit sandbox smoke test after building the CyberForge image.",
        ]
    result["limitations"] = [
        "The diagnostic does not change Docker Desktop, WSL, firewall, VPN, proxy or Windows security settings.",
        "It does not prove that every sandbox security control works; the explicit smoke test checks the existing image's loopback raw-socket capability only.",
        "Docker Desktop networking uses a VM/backend and may not map one-to-one to Windows host interfaces.",
    ]
    return result


def docker_sandbox_smoke_test(image: str, acknowledged: bool = False) -> dict[str, Any]:
    """Launch an inert capability probe in the existing image; never mounts or runs a sample."""
    if acknowledged is not True:
        raise PermissionError("Explicit approval is required to start the isolated Docker capability probe.")
    docker = shutil.which("docker")
    if not docker:
        return {"available": False, "passed": False, "reason": "docker_cli_missing"}
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,180}", str(image or "")):
        raise ValueError("Docker image name is invalid.")
    inspect = _run_command([docker, "image", "inspect", image], 6)
    if inspect.get("returncode") != 0:
        return {"available": False, "passed": False, "reason": "image_not_present", "detail": _safe_text(inspect.get("stderr"), 500)}
    probe = (
        "import os, socket, json\n"
        "raw_ok = False; packet_seen = False; default_routes = []; err = ''\n"
        "try:\n"
        "    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))\n"
        "    raw.bind(('lo', 0)); raw.settimeout(1.5); raw_ok = True\n"
        "    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "    udp.sendto(b'cyberforge-loopback-probe', ('127.0.0.1', 45454))\n"
        "    frame, _ = raw.recvfrom(65535); packet_seen = bool(frame)\n"
        "    udp.close(); raw.close()\n"
        "    with open('/proc/net/route', 'r', encoding='ascii') as f:\n"
        "        next(f, None)\n"
        "        for line in f:\n"
        "            fields = line.split()\n"
        "            if len(fields) >= 3 and fields[1] == '00000000': default_routes.append(fields[0])\n"
        "except Exception as exc:\n"
        "    err = type(exc).__name__\n"
        "print(json.dumps({'euid': os.geteuid(), 'loopback_raw_socket': raw_ok, 'loopback_packet_seen': packet_seen, 'default_routes': default_routes, 'default_route_absent': not default_routes, 'error': err}))\n"
    )
    command = [docker, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--cap-add", "NET_RAW",
               "--security-opt", "no-new-privileges", "--read-only", "--pids-limit", "16", "--memory", "96m",
               "--cpus", "0.5", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=4m", "--entrypoint", "python3",
               image, "-c", probe]
    run = _run_command(command, 18)
    data = {}
    for line in (run.get("stdout") or "").splitlines():
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict): data = parsed
        except Exception: pass
    passed = (run.get("returncode") == 0 and data.get("loopback_raw_socket") is True
              and data.get("loopback_packet_seen") is True and data.get("default_route_absent") is True
              and data.get("euid") == 0)
    return {"available": True, "passed": passed, "probe": data,
            "container_policy": {"network": "none", "capabilities": ["NET_RAW"], "cap_drop": "ALL",
                                  "no_new_privileges": True, "read_only_rootfs": True,
                                  "memory_mb": 96, "pids_limit": 16, "sample_mounted": False},
            "detail": "AF_PACKET observed a generated loopback packet and the --network none namespace had no default route." if passed else _safe_text(run.get("stderr") or run.get("stdout") or "Capability probe failed.", 700),
            "warning": "This probe verifies only a narrow capability path. It does not certify container escape resistance or host isolation."}


# -------- PCAP / PCAPNG metadata decoder --------

def _parse_pcap_records(data: bytes) -> tuple[list[tuple[float, int, bytes]], dict[str, Any]]:
    if len(data) < 24: raise ValueError("PCAP file is shorter than its global header.")
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats: raise ValueError("Unsupported PCAP magic. Expected classic PCAP or PCAPNG.")
    endian, divisor = formats[magic]
    _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", data[:24])
    if major != 2 or minor not in (3, 4): raise ValueError("Unsupported classic PCAP version.")
    if snaplen <= 0 or snaplen > 16 * 1024 * 1024: raise ValueError("PCAP snap length is outside limits.")
    records = []; pos = 24; truncated = False
    while pos + 16 <= len(data) and len(records) < MAX_PACKETS:
        sec, frac, caplen, origlen = struct.unpack(endian + "IIII", data[pos:pos+16]); pos += 16
        if caplen > snaplen or caplen > 262144 or pos + caplen > len(data):
            truncated = True; break
        packet = data[pos:pos+caplen]; pos += caplen
        if caplen:
            records.append((sec + frac / divisor, linktype, packet))
    return records, {"format": "pcap", "byte_order": "little" if endian == "<" else "big", "linktype": linktype,
                     "snaplen": snaplen, "records": len(records), "truncated": truncated or pos < len(data)}


def _parse_pcapng_records(data: bytes) -> tuple[list[tuple[float, int, bytes]], dict[str, Any]]:
    if len(data) < 28 or data[:4] != b"\x0a\x0d\x0d\x0a": raise ValueError("Invalid PCAPNG section header.")
    pos = 0; endian = None; interfaces: list[tuple[int, int, float, int]] = []; records = []; truncated = False
    while pos + 12 <= len(data) and len(records) < MAX_PACKETS:
        if data[pos:pos+4] == b"\x0a\x0d\x0d\x0a":
            if pos + 12 > len(data): break
            bom = data[pos+8:pos+12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else (">" if bom == b"\x1a\x2b\x3c\x4d" else None)
            if endian is None: raise ValueError("Invalid PCAPNG byte-order magic.")
            if pos > 0: interfaces = []  # each section has its own interface ID space
        if endian is None: raise ValueError("PCAPNG section byte order is missing.")
        block_type, block_len = struct.unpack(endian + "II", data[pos:pos+8])
        if block_len < 12 or block_len % 4 or pos + block_len > len(data):
            truncated = True; break
        block = data[pos:pos+block_len]
        trailing = struct.unpack(endian + "I", block[-4:])[0]
        if trailing != block_len: truncated = True; break
        body = block[8:-4]
        if block_type == 1 and len(body) >= 8:  # Interface Description Block
            linktype, _reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
            if snaplen <= 0 or snaplen > 16 * 1024 * 1024: snaplen = 262144
            # PCAPNG defaults to microsecond timestamps. if_tsresol (option 9)
            # can specify decimal or binary resolution; if_tsoffset (option 14)
            # is a signed seconds offset.
            ts_resolution = 1e-6; ts_offset = 0; opt = 8
            while opt + 4 <= len(body):
                code, size = struct.unpack(endian + "HH", body[opt:opt+4]); opt += 4
                if code == 0: break
                if opt + size > len(body): break
                value = body[opt:opt+size]; opt += (size + 3) & ~3
                if code == 9 and size == 1:
                    exponent = value[0] & 0x7F
                    ts_resolution = (2.0 ** -exponent) if value[0] & 0x80 else (10.0 ** -exponent)
                elif code == 14 and size == 8:
                    ts_offset = struct.unpack(endian + "q", value)[0]
            interfaces.append((linktype, snaplen, ts_resolution, ts_offset))
        elif block_type == 6 and len(body) >= 20:  # Enhanced Packet Block
            iface, thi, tlo, caplen, origlen = struct.unpack(endian + "IIIII", body[:20])
            if iface >= len(interfaces) or caplen > 262144 or 20 + ((caplen + 3) & ~3) > len(body): truncated = True
            else:
                linktype, snaplen, ts_resolution, ts_offset = interfaces[iface]
                if caplen <= snaplen:
                    packet = body[20:20+caplen]
                    records.append(((thi << 32 | tlo) * ts_resolution + ts_offset, linktype, packet))
        elif block_type == 2 and len(body) >= 20 and interfaces:  # Obsolete Packet Block
            iface, _drops, thi, tlo, caplen, origlen = struct.unpack(endian + "HHIIII", body[:20])
            if iface >= len(interfaces) or caplen > 262144 or 20 + ((caplen + 3) & ~3) > len(body):
                truncated = True
            else:
                linktype, snaplen, ts_resolution, ts_offset = interfaces[iface]
                if caplen <= snaplen:
                    packet = body[20:20+caplen]
                    records.append(((thi << 32 | tlo) * ts_resolution + ts_offset, linktype, packet))
        elif block_type == 3 and len(body) >= 4 and interfaces:  # Simple Packet Block
            (origlen,) = struct.unpack(endian + "I", body[:4]); caplen = min(origlen, len(body)-4, interfaces[0][1])
            if caplen: records.append((0.0, interfaces[0][0], body[4:4+caplen]))
        pos += block_len
    return records, {"format": "pcapng", "byte_order": "little" if endian == "<" else "big",
                     "interfaces": len(interfaces), "records": len(records), "truncated": truncated or pos < len(data)}


def _link_payload(linktype: int, packet: bytes) -> bytes | None:
    if linktype in (101, 12): return packet if packet and packet[0] >> 4 in (4, 6) else None  # RAW
    if linktype == 1:  # Ethernet, VLAN/QinQ supported
        if len(packet) < 14: return None
        proto = struct.unpack("!H", packet[12:14])[0]; pos = 14
        while proto in (0x8100, 0x88A8, 0x9100) and pos + 4 <= len(packet):
            proto = struct.unpack("!H", packet[pos+2:pos+4])[0]; pos += 4
        if proto == 0x0800 and packet[pos:pos+1] and packet[pos] >> 4 == 4: return packet[pos:]
        if proto == 0x86DD and packet[pos:pos+1] and packet[pos] >> 4 == 6: return packet[pos:]
        return None
    if linktype == 113:  # Linux cooked v1
        if len(packet) < 16: return None
        proto = struct.unpack("!H", packet[14:16])[0]; payload = packet[16:]
    elif linktype == 276:  # Linux cooked v2
        if len(packet) < 20: return None
        proto = struct.unpack("!H", packet[:2])[0]; payload = packet[20:]
    elif linktype == 0:  # BSD loopback / NULL
        if len(packet) < 5: return None
        family_le = struct.unpack("<I", packet[:4])[0]; family_be = struct.unpack(">I", packet[:4])[0]
        payload = packet[4:]
        if payload and payload[0] >> 4 in (4, 6) and (family_le in (2, 24, 28, 30) or family_be in (2, 24, 28, 30)): return payload
        return None
    else: return None
    if proto == 0x0800 and payload and payload[0] >> 4 == 4: return payload
    if proto == 0x86DD and payload and payload[0] >> 4 == 6: return payload
    return None


def _ip_transport(packet: bytes) -> dict[str, Any] | None:
    try:
        if not packet: return None
        version = packet[0] >> 4
        if version == 4:
            if len(packet) < 20: return None
            ihl = (packet[0] & 15) * 4; total = struct.unpack("!H", packet[2:4])[0]
            if ihl < 20 or len(packet) < ihl or total < ihl: return None
            frag = struct.unpack("!H", packet[6:8])[0]
            if frag & 0x1FFF: return {"src": socket.inet_ntop(socket.AF_INET, packet[12:16]), "dst": socket.inet_ntop(socket.AF_INET, packet[16:20]), "protocol": packet[9], "fragment": True}
            proto = packet[9]; src = socket.inet_ntop(socket.AF_INET, packet[12:16]); dst = socket.inet_ntop(socket.AF_INET, packet[16:20]); off = ihl
            payload = packet[off:min(total, len(packet))]
        elif version == 6:
            if len(packet) < 40: return None
            plen = struct.unpack("!H", packet[4:6])[0]; next_header = packet[6]
            src = socket.inet_ntop(socket.AF_INET6, packet[8:24]); dst = socket.inet_ntop(socket.AF_INET6, packet[24:40]); off = 40
            end = min(40 + plen, len(packet))
            for _ in range(8):
                if next_header in (0, 43, 60, 135, 139, 140):
                    if off + 2 > end: return None
                    nxt = packet[off]; size = (packet[off+1] + 1) * 8; next_header = nxt; off += size
                elif next_header == 44:
                    if off + 8 > end: return None
                    nxt = packet[off]; frag = struct.unpack("!H", packet[off+2:off+4])[0]; next_header = nxt; off += 8
                    if frag & 0xFFF8: return {"src": src, "dst": dst, "protocol": next_header, "fragment": True}
                elif next_header == 51:
                    if off + 2 > end: return None
                    nxt = packet[off]; size = (packet[off+1] + 2) * 4; next_header = nxt; off += size
                else: break
                if off > end: return None
            proto = next_header; payload = packet[off:end]
        else: return None
        row: dict[str, Any] = {"src": src, "dst": dst, "ip_version": version, "protocol_number": proto, "bytes": len(packet)}
        if proto == 6:
            if len(payload) < 20: return row
            sport, dport, seq, ack = struct.unpack("!HHII", payload[:12]); dataoff = (payload[12] >> 4) * 4
            if dataoff < 20 or len(payload) < dataoff: return row
            flags = payload[13]
            row.update({"protocol": "TCP", "src_port": sport, "dst_port": dport, "seq": seq, "ack": ack,
                        "flags": flags, "flag_names": [name for bit, name in ((1,"FIN"),(2,"SYN"),(4,"RST"),(8,"PSH"),(16,"ACK"),(32,"URG"),(64,"ECE"),(128,"CWR")) if flags & bit],
                        "syn": bool(flags & 2), "fin": bool(flags & 1), "rst": bool(flags & 4),
                        "payload": payload[dataoff:]})
        elif proto == 17:
            if len(payload) < 8: return row
            sport, dport, length = struct.unpack("!HHH", payload[:6])
            row.update({"protocol": "UDP", "src_port": sport, "dst_port": dport, "payload": payload[8:min(len(payload), max(8, length))]})
        else:
            row.update({"protocol": {1: "ICMP", 58: "ICMPv6"}.get(proto, f"IP-{proto}")})
            if proto in (1, 58) and len(payload) >= 2:
                row.update({"icmp_type": payload[0], "icmp_code": payload[1]})
        return row
    except Exception: return None


def _dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels = []; pos = offset; end_pos = None; jumps = 0; visited = set()
    while pos < len(packet):
        n = packet[pos]
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(packet): break
            ptr = ((n & 0x3F) << 8) | packet[pos+1]
            if ptr >= len(packet) or ptr in visited or jumps >= 12: break
            visited.add(ptr); jumps += 1
            if end_pos is None: end_pos = pos + 2
            pos = ptr; continue
        pos += 1
        if n == 0:
            return ".".join(labels)[:253], (end_pos if end_pos is not None else pos)
        if n > 63 or pos + n > len(packet): break
        labels.append(packet[pos:pos+n].decode("ascii", "replace")); pos += n
    return ".".join(labels)[:253], (end_pos if end_pos is not None else pos)


def _dns_metadata(packet: bytes) -> dict[str, Any] | None:
    try:
        if len(packet) < 12: return None
        ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
        if qd > 32 or an > 128: return None
        pos = 12; questions = []
        for _ in range(qd):
            name, pos = _dns_name(packet, pos)
            if pos + 4 > len(packet): return None
            qtype, qclass = struct.unpack("!HH", packet[pos:pos+4]); pos += 4
            questions.append({"name": name, "qtype": _dns_type(qtype), "qclass": qclass})
        answers = []
        for _ in range(min(an, 32)):
            name, pos = _dns_name(packet, pos)
            if pos + 10 > len(packet): break
            typ, cls, ttl, rdlen = struct.unpack("!HHIH", packet[pos:pos+10]); pos += 10
            raw = packet[pos:pos+rdlen]
            if pos + rdlen > len(packet): break
            pos += rdlen; item = {"name": name, "type": _dns_type(typ), "ttl": ttl}
            if typ == 1 and len(raw) == 4: item["address"] = socket.inet_ntop(socket.AF_INET, raw)
            elif typ == 28 and len(raw) == 16: item["address"] = socket.inet_ntop(socket.AF_INET6, raw)
            elif typ == 5:
                alias, _ = _dns_name(packet, pos-rdlen); item["cname"] = alias
            answers.append(item)
        return {"id": ident, "response": bool(flags & 0x8000), "rcode": flags & 15,
                "questions": questions, "answers": answers}
    except Exception: return None


def _dns_type(value: int) -> str:
    return {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",15:"MX",16:"TXT",28:"AAAA",33:"SRV",41:"OPT",255:"ANY"}.get(value, str(value))


def _clean_http_path(path: str) -> str:
    path = path.split("?", 1)[0].split("#", 1)[0]
    path = re.sub(r"/(?=[A-Za-z0-9_-]{28,}(?:/|$))[A-Za-z0-9_-]{28,}", "/[REDACTED_SEGMENT]", path)
    path = re.sub(r"(?i)(token|secret|password|api[_-]?key)=[^/&]+", r"\1=[REDACTED]", path)
    return _safe_text(path, 500)


def _http_message(data: bytes) -> dict[str, Any] | None:
    if not data: return None
    header_end = data.find(b"\r\n\r\n")
    if header_end < 0 or header_end > 16384: return None
    try: lines = data[:header_end].decode("iso-8859-1", "replace").split("\r\n")
    except Exception: return None
    if not lines: return None
    first = lines[0][:1000]; out: dict[str, Any] = {"type": "http_message"}
    m = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/(\d(?:\.\d)?)$", first, re.I)
    response = re.match(r"^HTTP/(\d(?:\.\d)?)\s+(\d{3})", first, re.I)
    if m:
        out.update({"message": "request", "method": m.group(1).upper(), "path": _clean_http_path(m.group(2)), "http_version": m.group(3)})
    elif response:
        out.update({"message": "response", "http_version": response.group(1), "status": int(response.group(2))})
    elif first.startswith("PRI * HTTP/2.0"):
        return {"type": "http2_preface", "message": "http2_preface"}
    else: return None
    safe_headers = {}
    for line in lines[1:80]:
        if ":" not in line: continue
        name, value = line.split(":", 1); key = name.strip().lower(); val = value.strip()
        if key in {"host", "content-type", "content-length", "user-agent", "server", "location", "accept", "connection"}:
            if key == "location": val = val.split("?", 1)[0]
            safe_headers[key] = _safe_text(val, 250)
    out["headers"] = safe_headers
    out["body_captured"] = False
    return out


def _is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _tls_hellos(stream: bytes) -> list[dict[str, Any]]:
    events = []; pos = 0; handshakes = bytearray(); record_index = 0
    while pos + 5 <= len(stream) and record_index < 128:
        content_type = stream[pos]; record_version = struct.unpack("!H", stream[pos+1:pos+3])[0]
        length = struct.unpack("!H", stream[pos+3:pos+5])[0]
        if length > 18432 or pos + 5 + length > len(stream): break
        fragment = stream[pos+5:pos+5+length]; record_index += 1; pos += 5 + length
        if content_type == 22: handshakes.extend(fragment)
        elif content_type == 21 and len(fragment) >= 2:
            events.append({"type": "tls_alert", "level": fragment[0], "description": fragment[1], "record_version": f"0x{record_version:04x}"})
        while len(handshakes) >= 4:
            htype = handshakes[0]; hlen = int.from_bytes(handshakes[1:4], "big")
            if hlen > 65536 or len(handshakes) < 4 + hlen: break
            body = bytes(handshakes[4:4+hlen]); del handshakes[:4+hlen]
            if htype == 1:
                parsed = _parse_client_hello(body, record_version)
                if parsed: events.append(parsed)
            elif htype == 2:
                parsed = _parse_server_hello(body, record_version)
                if parsed: events.append(parsed)
            elif htype == 11:
                events.append({"type": "tls_certificate_message", "certificate_bytes_visible": len(body),
                               "certificate_content_exported": False,
                               "note": "Certificate handshake metadata only; encrypted TLS 1.3 certificate messages are not visible."})
            elif htype == 8:
                events.append({"type": "tls_encrypted_extensions", "bytes": len(body)})
    return events


def _parse_client_hello(body: bytes, record_version: int) -> dict[str, Any] | None:
    try:
        p = 0; legacy = struct.unpack("!H", body[p:p+2])[0]; p += 34
        sid_len = body[p]; p += 1 + sid_len
        clen = struct.unpack("!H", body[p:p+2])[0]; p += 2
        if clen % 2 or p + clen + 1 > len(body): return None
        ciphers = list(struct.unpack("!" + "H"*(clen//2), body[p:p+clen])); p += clen
        comp_len = body[p]; p += 1 + comp_len
        ext_types = []; server_name = ""; alpn = []; versions = []; groups = []; sigalgs = []; point_formats = []
        if p + 2 <= len(body):
            ext_len = struct.unpack("!H", body[p:p+2])[0]; p += 2; end = min(p+ext_len, len(body))
            while p + 4 <= end:
                etype, size = struct.unpack("!HH", body[p:p+4]); p += 4
                if p + size > end: break
                ext = body[p:p+size]; p += size; ext_types.append(etype)
                if etype == 0 and len(ext) >= 5:
                    q = 2
                    while q + 3 <= len(ext):
                        nt = ext[q]; ln = struct.unpack("!H", ext[q+1:q+3])[0]; q += 3
                        if q + ln > len(ext): break
                        if nt == 0: server_name = ext[q:q+ln].decode("ascii", "replace")[:253]
                        q += ln
                elif etype == 16 and len(ext) >= 2:
                    q = 2
                    while q < len(ext):
                        ln = ext[q]; q += 1
                        if q + ln > len(ext): break
                        alpn.append(ext[q:q+ln].decode("ascii", "replace")[:40]); q += ln
                elif etype == 43 and len(ext) >= 1:
                    q = 1
                    while q + 2 <= len(ext): versions.append(f"0x{struct.unpack('!H', ext[q:q+2])[0]:04x}"); q += 2
                elif etype == 10 and len(ext) >= 2:
                    n = struct.unpack("!H", ext[:2])[0]
                    groups = [hex(x) for x in struct.unpack("!"+"H"*(min(n, len(ext)-2)//2), ext[2:2+min(n,len(ext)-2)])]
                elif etype == 13 and len(ext) >= 2:
                    n = struct.unpack("!H", ext[:2])[0]
                    sigalgs = [hex(x) for x in struct.unpack("!"+"H"*(min(n,len(ext)-2)//2), ext[2:2+min(n,len(ext)-2)])]
                elif etype == 11 and len(ext) >= 1:
                    n = ext[0]; point_formats = list(ext[1:1+min(n,len(ext)-1)])
        clean_ciphers = [x for x in ciphers if not _is_grease(x)]
        clean_exts = [x for x in ext_types if not _is_grease(x)]
        clean_groups = [x for x in groups if not _is_grease(int(x,16))]
        fp_material = ",".join([str(legacy), "-".join(map(str,clean_ciphers)), "-".join(map(str,clean_exts)),
                                 "-".join(x[2:] for x in clean_groups), "-".join(map(str,point_formats))])
        return {"type": "tls_client_hello", "sni": server_name or None, "legacy_version": f"0x{legacy:04x}",
                "record_version": f"0x{record_version:04x}", "cipher_suites": [f"0x{x:04x}" for x in clean_ciphers[:80]],
                "extension_types": clean_exts[:80], "supported_versions": versions[:16], "alpn": alpn[:16],
                "supported_groups": clean_groups[:40], "signature_algorithms": sigalgs[:40],
                "ja3_like_sha256": hashlib.sha256(fp_material.encode()).hexdigest(),
                "tls_decrypted": False, "payload_exported": False}
    except Exception: return None


def _parse_server_hello(body: bytes, record_version: int) -> dict[str, Any] | None:
    try:
        p = 34; sid_len = body[p]; p += 1 + sid_len
        cipher = struct.unpack("!H", body[p:p+2])[0]; p += 3
        selected = None; alpn = []
        if p + 2 <= len(body):
            n = struct.unpack("!H", body[p:p+2])[0]; p += 2; end = min(p+n, len(body))
            while p + 4 <= end:
                et, sz = struct.unpack("!HH", body[p:p+4]); p += 4; ext = body[p:p+sz]; p += sz
                if et == 43 and len(ext) >= 2: selected = f"0x{struct.unpack('!H',ext[:2])[0]:04x}"
                elif et == 16 and len(ext) >= 3:
                    ln = ext[2]; alpn.append(ext[3:3+ln].decode("ascii","replace")[:40])
        return {"type":"tls_server_hello", "legacy_version":f"0x{struct.unpack('!H',body[:2])[0]:04x}",
                "record_version":f"0x{record_version:04x}", "selected_version":selected,
                "selected_cipher":f"0x{cipher:04x}", "alpn":alpn[:8], "tls_decrypted":False}
    except Exception: return None


def _stream_reassemble(chunks: list[tuple[int, bytes]]) -> bytes:
    if not chunks: return b""
    chunks.sort(key=lambda x: x[0]); out = bytearray(); end_seq = None
    for seq, payload in chunks:
        if not payload: continue
        if end_seq is None: out.extend(payload); end_seq = (seq + len(payload)) & 0xFFFFFFFF; continue
        if seq == end_seq:
            out.extend(payload); end_seq = (end_seq + len(payload)) & 0xFFFFFFFF
        elif seq < end_seq < seq + len(payload):
            overlap = end_seq - seq; out.extend(payload[overlap:]); end_seq = (end_seq + len(payload)-overlap) & 0xFFFFFFFF
        if len(out) >= MAX_STREAM_BYTES: break
    return bytes(out[:MAX_STREAM_BYTES])


def decode_pcap(data: bytes) -> dict[str, Any]:
    """Decode bounded PCAP/PCAPNG to metadata-only timeline; never return payload bytes."""
    if not isinstance(data, (bytes, bytearray)): raise ValueError("PCAP input must be bytes.")
    data = bytes(data)
    if not data or len(data) > MAX_PCAP_BYTES: raise ValueError("PCAP input is empty or exceeds the 2 MiB limit.")
    if data[:4] == b"\x0a\x0d\x0d\x0a": records, fmt = _parse_pcapng_records(data)
    else: records, fmt = _parse_pcap_records(data)
    events: list[dict[str, Any]] = []; flow_map: dict[tuple, dict[str, Any]] = {}; tcp_chunks: dict[tuple, list[tuple[int,bytes]]] = {}
    unsupported = 0; malformed = 0; parsed = 0
    for ts, link, frame in records:
        ip = _link_payload(link, frame)
        if ip is None: unsupported += 1; continue
        row = _ip_transport(ip)
        if not row: malformed += 1; continue
        parsed += 1
        proto = row.get("protocol"); payload = row.get("payload", b"")
        key = (row.get("src"), row.get("src_port"), row.get("dst"), row.get("dst_port"), proto)
        flow = flow_map.setdefault(key, {"src": row.get("src"), "src_port": row.get("src_port"), "dst": row.get("dst"),
            "dst_port": row.get("dst_port"), "protocol": proto, "packets": 0, "bytes": 0, "first_seen": ts, "last_seen": ts})
        flow["packets"] += 1; flow["bytes"] += row.get("bytes", 0); flow["last_seen"] = ts
        if proto == "UDP" and (row.get("src_port") == 53 or row.get("dst_port") == 53):
            dns = _dns_metadata(payload)
            if dns:
                for q in dns.get("questions", [])[:8]:
                    events.append({"time": ts, "type": "dns_response" if dns.get("response") else "dns_query",
                                   "data": {"domain": q.get("name"), "qtype": q.get("qtype"), "rcode": dns.get("rcode"),
                                            "answers": dns.get("answers", [])[:8]}})
        if proto == "TCP" and payload and row.get("seq") is not None and len(tcp_chunks) < MAX_TCP_STREAMS:
            chunks = tcp_chunks.setdefault(key, [])
            if sum(len(x[1]) for x in chunks) < MAX_STREAM_BYTES: chunks.append((row["seq"], payload[:MAX_STREAM_BYTES]))
    for key, chunks in tcp_chunks.items():
        stream = _stream_reassemble(chunks)
        if not stream: continue
        if key[1] == 53 or key[3] == 53:
            if len(stream) >= 14:
                n = struct.unpack("!H", stream[:2])[0]
                dns = _dns_metadata(stream[2:2+min(n, len(stream)-2)]) if n <= len(stream)-2 else None
                if dns:
                    for q in dns.get("questions", [])[:8]:
                        events.append({"time": flow_map.get(key, {}).get("first_seen", 0),
                                       "type": "dns_response" if dns.get("response") else "dns_query",
                                       "data": {"domain": q.get("name"), "qtype": q.get("qtype"), "rcode": dns.get("rcode"), "answers": dns.get("answers", [])[:8], "transport": "TCP"}})
        http = _http_message(stream)
        if http:
            events.append({"time": flow_map.get(key, {}).get("first_seen", 0),
                           "type": "http_" + http.get("message", "metadata"), "data": {k:v for k,v in http.items() if k not in {"type","message"}}})
        for tls in _tls_hellos(stream):
            flow = flow_map.get(key, {})
            events.append({"time": flow.get("first_seen", 0), "type": tls["type"], "data": {k:v for k,v in tls.items() if k != "type"}})
    events.sort(key=lambda x: float(x.get("time") or 0))
    events = events[:MAX_DECODE_EVENTS]
    protocol_counts = {}
    for f in flow_map.values(): protocol_counts[f["protocol"]] = protocol_counts.get(f["protocol"], 0) + 1
    return {"schema": "cyberforge.pcap-analysis.v1", "decoded_at": _utc(), "capture": {**fmt, "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "parsed_ip_packets": parsed, "unsupported_link_packets": unsupported,
            "malformed_packets": malformed, "limits": {"max_file_bytes": MAX_PCAP_BYTES, "max_records": MAX_PACKETS}},
            "summary": {"flows": len(flow_map), "events": len(events), "protocol_flows": protocol_counts,
                        "dns_queries": sum(x["type"] == "dns_query" for x in events),
                        "http_messages": sum(x["type"].startswith("http_") for x in events),
                        "tls_hellos": sum(x["type"] in {"tls_client_hello","tls_server_hello"} for x in events)},
            "flows": list(flow_map.values())[:1500], "timeline": events,
            "privacy": {"payload_exported": False, "http_query_values_exported": False,
                        "authorization_headers_exported": False, "tls_decryption": False,
                        "certificate_bodies_exported": False, "note": "HTTP/TLS metadata only; TLS application data is not decrypted."},
            "coverage": {"linktypes_supported": [0,1,12,101,113,276], "pcapng_supported": True,
                         "tcp_reassembly": "bounded, directional, best-effort; out-of-order/overlap handling is conservative",
                         "limitations": ["TLS 1.3 encrypted handshake details beyond visible ClientHello/ServerHello are unavailable.",
                                         "Encrypted HTTP/2 or HTTP/3 application requests are not decoded.",
                                         "No process PID is inferred from packet metadata alone; use NetLab socket-owner events for attribution."]}}


def docker_preflight_summary(diagnostics: dict[str, Any]) -> dict[str, Any]:
    checks = diagnostics.get("checks", []) if isinstance(diagnostics, dict) else []
    ok = [x.get("name") for x in checks if isinstance(x, dict) and x.get("ok")]
    failed = [x.get("name") for x in checks if isinstance(x, dict) and not x.get("ok")]
    return {"ready_for_netlab": bool(diagnostics.get("daemon_reachable") and diagnostics.get("linux_container_engine")),
            "passed_checks": ok, "failed_checks": failed,
            "host_platform": diagnostics.get("host_platform"), "engine": diagnostics.get("engine", {})}
