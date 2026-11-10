#!/usr/bin/env python3
"""Bounded loopback-only packet capture and socket-owner attribution for NetLab."""
from __future__ import annotations
import os
import socket
import struct
import threading
import time
from pathlib import Path

MAX_PCAP_BYTES = 2 * 1024 * 1024
MAX_PACKETS = 12000


def _decode_endpoint(raw: str):
    try:
        addr, port = raw.split(":", 1)
        return addr, int(port, 16)
    except Exception:
        return "", 0


def _proc_net_rows(proto: str):
    names = {"tcp": ("tcp", "tcp6"), "udp": ("udp", "udp6")}.get(proto, ())
    for name in names:
        try:
            lines = Path("/proc/net/" + name).read_text().splitlines()[1:]
        except Exception:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            local, remote = _decode_endpoint(fields[1]), _decode_endpoint(fields[2])
            inode = fields[9]
            if inode.isdigit() and local[1] and remote[1]:
                yield local[1], remote[1], inode


def socket_owner(proto: str, local_port: int, remote_port: int) -> dict | None:
    """Best-effort PID lookup from /proc socket inode; short-lived sockets may be missed."""
    inodes = {inode for lp, rp, inode in _proc_net_rows(proto)
              if lp == int(local_port) and rp == int(remote_port)}
    if not inodes:
        return None
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            pid = int(proc.name)
            for fd in (proc / "fd").iterdir():
                try:
                    link = os.readlink(fd)
                except OSError:
                    continue
                if link.startswith("socket:[") and link.endswith("]") and link[8:-1] in inodes:
                    try:
                        name = (proc / "comm").read_text().strip()[:120]
                    except Exception:
                        name = "unknown"
                    return {"pid": pid, "process": name, "attribution": "proc_socket_inode"}
        except Exception:
            continue
    return None


def _normalize_loopback_packet(packet: bytes) -> bytes | None:
    """AF_PACKET may expose loopback's synthetic Ethernet header on Linux.

    Normalize either raw IP or Ethernet/VLAN-wrapped IP to an IP datagram so the
    classic PCAP DLT_RAW header written by this collector remains truthful.
    """
    if not packet:
        return None
    if packet[0] >> 4 in (4, 6):
        return packet
    if len(packet) < 14:
        return None
    proto = struct.unpack("!H", packet[12:14])[0]
    pos = 14
    while proto in (0x8100, 0x88A8, 0x9100) and pos + 4 <= len(packet):
        proto = struct.unpack("!H", packet[pos+2:pos+4])[0]
        pos += 4
    payload = packet[pos:]
    if proto == 0x0800 and payload and payload[0] >> 4 == 4:
        return payload
    if proto == 0x86DD and payload and payload[0] >> 4 == 6:
        return payload
    return None


def _parse_ip_flow(packet: bytes):
    """Parse bounded IP/TCP/UDP headers only; never decode application payload."""
    try:
        if not packet:
            return None
        version = packet[0] >> 4
        if version == 4:
            if len(packet) < 20:
                return None
            ihl = (packet[0] & 15) * 4
            if ihl < 20 or len(packet) < ihl + 4:
                return None
            proto = packet[9]
            src = socket.inet_ntop(socket.AF_INET, packet[12:16])
            dst = socket.inet_ntop(socket.AF_INET, packet[16:20])
            pos = ihl
        elif version == 6:
            if len(packet) < 44:
                return None
            proto = packet[6]
            src = socket.inet_ntop(socket.AF_INET6, packet[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, packet[24:40])
            pos = 40
        else:
            return None
        if proto not in (6, 17) or len(packet) < pos + 4:
            return {"src": src, "dst": dst, "protocol": "ICMP" if proto in (1, 58) else str(proto)}
        sport, dport = struct.unpack("!HH", packet[pos:pos+4])
        return {"src": src, "dst": dst, "protocol": "TCP" if proto == 6 else "UDP",
                "src_port": sport, "dst_port": dport}
    except Exception:
        return None


class LoopbackPcapCapture:
    def __init__(self, path: str | Path, max_bytes: int = MAX_PCAP_BYTES):
        self.path = Path(path)
        self.max_bytes = max(64 * 1024, min(int(max_bytes), MAX_PCAP_BYTES))
        self.sock = None
        self.thread = None
        self.stop_event = threading.Event()
        self.packet_count = 0
        self.flow_count = 0
        self.bytes_written = 0
        self.error = None
        self.flows: list[dict] = []
        self._flow_keys = set()
        self._file = None
        self.started = None
        self.available = False

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            self.sock.bind(("lo", 0))
            self.sock.settimeout(0.2)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = self.path.open("wb")
            try: os.chmod(self.path, 0o600)
            except OSError: pass
            # Classic PCAP little-endian, version 2.4, DLT_RAW (101, IP packet starts at byte 0).
            self._file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
            self._file.flush()
            self.started = time.time()
            self.available = True
            self.thread = threading.Thread(target=self._capture, name="cf-netlab-pcap", daemon=True)
            self.thread.start()
        except Exception as exc:
            self.error = type(exc).__name__
            self.available = False
            try:
                if self.sock: self.sock.close()
            except Exception: pass
            self.sock = None
            try:
                if self._file: self._file.close()
            except Exception: pass
            self._file = None
        return self

    def _capture(self):
        try:
            while not self.stop_event.is_set() and self.packet_count < MAX_PACKETS:
                if self._file and self._file.tell() >= self.max_bytes:
                    self.error = "pcap_size_limit_reached"
                    break
                try:
                    packet, _ = self.sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                # Linux AF_PACKET on lo can return a synthetic Ethernet header.
                # Normalize before writing DLT_RAW and before extracting flow metadata.
                packet = _normalize_loopback_packet(packet)
                if packet is None:
                    continue
                caplen = min(len(packet), 1500)
                record_size = 16 + caplen
                if self._file.tell() + record_size > self.max_bytes:
                    self.error = "pcap_size_limit_reached"
                    break
                now = time.time()
                sec = int(now); usec = int((now - sec) * 1_000_000)
                self._file.write(struct.pack("<IIII", sec, usec, caplen, len(packet)))
                self._file.write(packet[:caplen])
                self.packet_count += 1
                self.bytes_written += record_size
                flow = _parse_ip_flow(packet)
                if flow:
                    key = (flow.get("src"), flow.get("dst"), flow.get("protocol"),
                           flow.get("src_port"), flow.get("dst_port"))
                    if key not in self._flow_keys and len(self.flows) < 2000:
                        self._flow_keys.add(key)
                        self.flows.append({"time": now, **flow})
            if self._file:
                self._file.flush()
        except Exception as exc:
            self.error = type(exc).__name__

    def stop(self):
        self.stop_event.set()
        try:
            if self.sock: self.sock.close()
        except Exception: pass
        if self.thread:
            self.thread.join(timeout=2)
        try:
            if self._file:
                self._file.flush(); self._file.close()
        except Exception: pass
        self.sock = None; self._file = None
        return {"available": self.available, "packet_count": self.packet_count,
                "size_bytes": self.path.stat().st_size if self.path.is_file() else 0,
                "flow_count": len(self.flows), "error": self.error,
                "interface": "lo", "scope": "Docker network namespace loopback only"}
