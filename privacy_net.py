"""Privacy-first, fail-closed search and read-only web access for CyberForge.

The module deliberately does not persist routes, proxy credentials, browser cookies,
queries, page text or browsing history. It is a text reader, not a general-purpose
JavaScript browser. Tor requests use SOCKS5 domain addressing (remote DNS).
"""
from __future__ import annotations

import base64
import http.client
import html
import html.parser
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
from typing import Any

_LOCK = threading.RLock()
_STATE: dict[str, Any] = {
    "route": "direct",
    "tor_host": "127.0.0.1",
    "tor_port": 9050,
    "http_proxy": "",
    "searxng_url": "",
    "configured_at": None,
}
_MAX_PAGE = 1_500_000
_MAX_TEXT = 36_000
_MAX_RESULTS = 25
_TIMEOUT = 16
_USER_AGENT = "CyberForge-Private-Reader/1.6 (text-only; local privacy session)"
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home", ".test", ".invalid", ".example")


class PrivacyError(ValueError):
    pass


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("SOCKS5 response ended unexpectedly.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _snapshot() -> dict[str, Any]:
    with _LOCK:
        return dict(_STATE)


def _safe_proxy_display(value: str) -> str:
    try:
        p = urllib.parse.urlsplit(value)
        if not p.hostname:
            return ""
        port = p.port or (443 if p.scheme == "https" else 80)
        return f"{p.scheme}://{p.hostname}:{port}"
    except Exception:
        return "configured proxy"


def _validate_host_syntax(host: str, route: str) -> str:
    host = (host or "").strip().rstrip(".").lower()
    if not host or len(host) > 253 or any(ord(c) < 33 for c in host):
        raise PrivacyError("Hostname không hợp lệ.")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise PrivacyError("Hostname IDN không hợp lệ.") from None
    if host in {"localhost", "localhost.localdomain", "ip6-localhost"} or host.endswith(_BLOCKED_SUFFIXES):
        if not (route == "tor" and host.endswith(".onion")):
            raise PrivacyError("Reader chỉ cho phép hostname public; địa chỉ localhost/private bị chặn.")
    if host.endswith(".onion") and route != "tor":
        raise PrivacyError("Địa chỉ .onion chỉ được truy cập khi route Tor SOCKS5 đang bật.")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        # Hostname: accept DNS syntax only; a Tor route sends it to SOCKS5 without local lookup.
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$", host):
            raise PrivacyError("Hostname phải là FQDN public hợp lệ.")
    else:
        if not ip.is_global:
            raise PrivacyError("Địa chỉ IP private, loopback, link-local hoặc reserved bị chặn.")
    return host


def _validate_url(url: str, route: str) -> urllib.parse.SplitResult:
    if not isinstance(url, str) or len(url) > 2048:
        raise PrivacyError("URL không hợp lệ hoặc vượt 2048 ký tự.")
    p = urllib.parse.urlsplit(url.strip())
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise PrivacyError("Chỉ hỗ trợ URL HTTP/HTTPS hợp lệ, không chứa userinfo.")
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        raise PrivacyError("Cổng URL không hợp lệ.") from None
    expected = 443 if p.scheme == "https" else 80
    if port != expected:
        raise PrivacyError("Private Web Reader chỉ truy cập cổng 80/443.")
    _validate_host_syntax(p.hostname, route)
    return p


def _resolve_public(host: str, port: int) -> str:
    """Resolve once, reject the whole answer set if any address is not globally routable."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RuntimeError(f"DNS lookup thất bại: {type(exc).__name__}") from None
    addresses: list[str] = []
    for info in infos:
        address = info[4][0].split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise PrivacyError("DNS trả về địa chỉ không hợp lệ.") from None
        if not ip.is_global:
            raise PrivacyError("DNS trả về địa chỉ không public; từ chối để chống SSRF/DNS rebinding cơ bản.")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise RuntimeError("Không có địa chỉ public cho hostname.")
    return addresses[0]


def _socks5_connect(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: float = _TIMEOUT) -> socket.socket:
    """SOCKS5 CONNECT with hostname ATYP=DOMAIN: the proxy performs remote DNS."""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        hello = _recv_exact(sock, 2)
        if hello != b"\x05\x00":
            raise RuntimeError("SOCKS5 không chấp nhận phương thức no-auth.")
        try:
            target_ip = ipaddress.ip_address(target_host.strip("[]"))
        except ValueError:
            domain = target_host.encode("idna")
            if not domain or len(domain) > 255:
                raise PrivacyError("Hostname vượt giới hạn SOCKS5.")
            address = b"\x03" + bytes([len(domain)]) + domain
        else:
            if target_ip.version == 4:
                address = b"\x01" + target_ip.packed
            else:
                address = b"\x04" + target_ip.packed
        sock.sendall(b"\x05\x01\x00" + address + int(target_port).to_bytes(2, "big"))
        head = _recv_exact(sock, 4)
        if len(head) != 4 or head[0] != 5 or head[1] != 0:
            raise RuntimeError("Tor SOCKS5 CONNECT thất bại.")
        atyp = head[3]
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 4:
            _recv_exact(sock, 16)
        elif atyp == 3:
            n = _recv_exact(sock, 1)
            _recv_exact(sock, n[0])
        else:
            raise RuntimeError("SOCKS5 trả về address type không hợp lệ.")
        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def _wireguard_status() -> dict[str, Any]:
    if not __import__("sys").platform.startswith("linux"):
        return {"available": False, "active": False, "interfaces": [], "default_route_via_wireguard": False,
                "notice": "WireGuard route detection currently supports Linux hosts only."}
    wg = __import__("shutil").which("wg")
    ip = __import__("shutil").which("ip")
    if not wg or not ip:
        return {"available": bool(wg), "active": False, "interfaces": [], "default_route_via_wireguard": False,
                "notice": "Install/use wg and iproute2 on the host; CyberForge does not alter VPN configuration."}
    try:
        p = subprocess.run([wg, "show", "interfaces"], capture_output=True, text=True, timeout=5,
                           shell=False, stdin=subprocess.DEVNULL)
        interfaces = [x for x in (p.stdout or "").split() if re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", x)] if p.returncode == 0 else []
        route = subprocess.run([ip, "route", "get", "1.1.1.1"], capture_output=True, text=True, timeout=5,
                               shell=False, stdin=subprocess.DEVNULL)
        route_text = (route.stdout or "").strip()[:500]
        via = next((name for name in interfaces if re.search(r"\bdev\s+" + re.escape(name) + r"\b", route_text)), None)
        return {"available": True, "active": bool(interfaces), "interfaces": interfaces,
                "default_route_via_wireguard": bool(via), "default_route_interface": via,
                "route_text": route_text,
                "notice": "Detection is not proof of a full-tunnel kill switch or DNS routing. Verify AllowedIPs, DNS and firewall policy on the host."}
    except Exception as exc:
        return {"available": True, "active": False, "interfaces": [], "default_route_via_wireguard": False,
                "notice": f"WireGuard status could not be verified: {type(exc).__name__}."}


def _tor_probe(host: str, port: int) -> dict[str, Any]:
    try:
        s = socket.create_connection((host, port), timeout=1.5)
        with s:
            s.settimeout(1.5)
            s.sendall(b"\x05\x01\x00")
            response = _recv_exact(s, 2)
        ready = response == b"\x05\x00"
        return {"available": ready, "endpoint": f"{host}:{port}",
                "notice": "SOCKS handshake passed; Tor circuit and egress have not yet been verified." if ready else "SOCKS endpoint did not negotiate no-auth."}
    except OSError as exc:
        return {"available": False, "endpoint": f"{host}:{port}", "notice": f"Tor SOCKS endpoint unavailable: {type(exc).__name__}."}


def configure_privacy(payload: dict[str, Any]) -> dict[str, Any]:
    route = str(payload.get("route", "direct"))
    if route not in {"direct", "tor", "http_proxy", "wireguard_system"}:
        raise PrivacyError("Route phải là direct, tor, http_proxy hoặc wireguard_system.")
    host = str(payload.get("tor_host", "127.0.0.1")).strip()
    try:
        # A literal IP is required to avoid a local DNS query for the SOCKS endpoint.
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        raise PrivacyError("Tor SOCKS endpoint phải là IP literal, ví dụ 127.0.0.1.") from None
    port = int(payload.get("tor_port", 9050))
    if not 1 <= port <= 65535:
        raise PrivacyError("Tor SOCKS port không hợp lệ.")
    proxy = str(payload.get("http_proxy", "")).strip()
    if route == "http_proxy":
        pp = urllib.parse.urlsplit(proxy)
        if pp.scheme != "http" or not pp.hostname or pp.path not in {"", "/"} or pp.query or pp.fragment:
            raise PrivacyError("HTTP proxy phải có dạng http://[user:pass@]host:port, không có path/query.")
        try:
            proxy_port = pp.port or 80
        except ValueError:
            raise PrivacyError("HTTP proxy port không hợp lệ.") from None
        if not 1 <= proxy_port <= 65535:
            raise PrivacyError("HTTP proxy port không hợp lệ.")
        if pp.username is not None or pp.password is not None:
            try:
                proxy_ip = ipaddress.ip_address(pp.hostname.strip("[]"))
                local_proxy = proxy_ip.is_loopback
            except ValueError:
                local_proxy = pp.hostname.lower() in {"localhost", "localhost.localdomain"}
            if not local_proxy:
                raise PrivacyError("Không gửi Basic credentials qua HTTP proxy từ xa vì thông tin xác thực không được mã hóa. Hãy dùng proxy local hoặc thiết lập một tunnel/VPN an toàn bên ngoài.")
    searx = str(payload.get("searxng_url", "")).strip().rstrip("/")
    if searx:
        sp = urllib.parse.urlsplit(searx)
        if sp.scheme != "https" or not sp.hostname or sp.username or sp.password or sp.query or sp.fragment:
            raise PrivacyError("SearXNG endpoint phải là HTTPS hợp lệ, không chứa userinfo/query.")
        if sp.port not in (None, 443):
            raise PrivacyError("SearXNG endpoint từ xa phải dùng cổng HTTPS chuẩn 443.")
    with _LOCK:
        _STATE.update({"route": route, "tor_host": host, "tor_port": port,
                       "http_proxy": proxy if route == "http_proxy" else "",
                       "searxng_url": searx, "configured_at": time.time()})
    return privacy_status()


def privacy_status() -> dict[str, Any]:
    s = _snapshot()
    route = s["route"]
    tor = _tor_probe(s["tor_host"], s["tor_port"])
    wg = _wireguard_status()
    if route == "tor":
        ready = tor["available"]
        state = "ready" if ready else "blocked"
        detail = "Requests use SOCKS5 hostname addressing and remote DNS. No direct fallback is permitted." if ready else "Tor route selected but SOCKS is unavailable. All web requests fail closed."
    elif route == "http_proxy":
        ready = bool(s["http_proxy"])
        state = "configured" if ready else "blocked"
        detail = "All reader/search requests use the explicitly configured proxy; redirects and direct fallback are disabled." if ready else "Proxy is missing; requests fail closed."
    elif route == "wireguard_system":
        ready = bool(wg.get("default_route_via_wireguard"))
        state = "detected" if ready else "blocked"
        detail = "OS default route appears to use a WireGuard interface. DNS/full-tunnel behavior is not proven." if ready else "No WireGuard default route detected; requests fail closed."
    else:
        ready = True
        state = "direct"
        detail = "Requests use the host network and local DNS. This is not an anonymous/private route."
    return {"route": route, "state": state, "ready": ready, "detail": detail,
            "tor": tor, "tor_host": s["tor_host"], "tor_port": s["tor_port"], "wireguard": wg,
            "proxy_display": _safe_proxy_display(s["http_proxy"]),
            "searxng_url": s["searxng_url"], "searxng_configured": bool(s["searxng_url"]), "session_only": True,
            "browser": {"cookies": "disabled", "cache": "disabled", "history": "not persisted",
                        "javascript": "disabled", "downloads": "disabled", "content": "sanitized text reader"},
            "notice": "Không có ẩn danh tuyệt đối. Website vẫn có thể nhận diện qua nội dung tài khoản, fingerprint, hành vi hoặc dữ liệu bạn tự gửi. Route status không chứng minh toàn bộ hệ điều hành đã được bảo vệ."}


def _connect_route(host: str, port: int, scheme: str, route: str, state: dict[str, Any]) -> http.client.HTTPConnection:
    if route == "tor":
        tor = _tor_probe(state["tor_host"], state["tor_port"])
        if not tor["available"]:
            raise RuntimeError("Tor SOCKS5 không sẵn sàng; fail-closed, không chuyển sang direct.")
        sock = _socks5_connect(state["tor_host"], state["tor_port"], host, port)
    elif route in {"direct", "wireguard_system"}:
        if route == "wireguard_system":
            wg = _wireguard_status()
            if not wg.get("default_route_via_wireguard"):
                raise RuntimeError("WireGuard default route không hoạt động; request bị chặn, không fallback direct.")
        address = _resolve_public(host, port)
        sock = socket.create_connection((address, port), timeout=_TIMEOUT)
    else:
        raise RuntimeError("Route này dùng HTTP proxy handler riêng.")
    sock.settimeout(_TIMEOUT)
    if scheme == "https":
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=host)
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(host, port, timeout=_TIMEOUT, context=context)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=_TIMEOUT)
    conn.sock = sock
    return conn


def _fetch_bytes(url: str, max_bytes: int = _MAX_PAGE, timeout: int = _TIMEOUT) -> tuple[int, dict[str, str], bytes, str]:
    state = _snapshot()
    route = state["route"]
    p = _validate_url(url, route)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    path = urllib.parse.urlunsplit(("", "", p.path or "/", p.query, ""))
    headers = {"User-Agent": _USER_AGENT, "Accept": "text/html, text/plain, application/json;q=0.9", "Accept-Encoding": "identity", "Connection": "close"}
    if route == "http_proxy":
        proxy = state.get("http_proxy")
        if not proxy:
            raise RuntimeError("HTTP proxy chưa cấu hình; fail-closed.")
        # Use an explicit proxy socket/tunnel rather than urllib.ProxyHandler.
        # ProxyHandler can bypass configured proxies for NO_PROXY hosts and silently
        # fall back to a direct handler. This path never creates a direct connection.
        pp = urllib.parse.urlsplit(proxy)
        proxy_host = pp.hostname or ""
        proxy_port = pp.port or 80
        proxy_headers: dict[str, str] = {}
        if pp.username is not None:
            user = urllib.parse.unquote(pp.username)
            password = urllib.parse.unquote(pp.password or "")
            token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
            proxy_headers["Proxy-Authorization"] = "Basic " + token
        if p.scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                proxy_host, proxy_port, timeout=timeout, context=ssl.create_default_context())
            conn.set_tunnel(host, port, headers=proxy_headers)
            request_target = path
            request_headers = dict(headers)
            request_headers["Host"] = host
        else:
            conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
            request_target = url
            request_headers = dict(headers)
            request_headers["Host"] = host
            if "Proxy-Authorization" in proxy_headers:
                request_headers.update(proxy_headers)
        try:
            conn.request("GET", request_target, headers=request_headers)
            resp = conn.getresponse()
            status = int(resp.status)
            h = {k.lower(): v for k, v in resp.getheaders()}
            if 300 <= status < 400:
                raise RuntimeError("Redirect bị chặn. Hãy kiểm tra URL đích và mở lại thủ công.")
            if status == 407:
                raise RuntimeError("HTTP proxy yêu cầu xác thực hoặc từ chối credentials.")
            ctype = h.get("content-type", "")
            if not any(x in ctype.lower() for x in ("text/html", "text/plain", "application/json", "application/xhtml+xml")):
                raise PrivacyError("Nội dung không phải HTML/text/JSON; từ chối tải binary.")
            try:
                if int(h.get("content-length", "0") or 0) > max_bytes:
                    raise PrivacyError("Trang vượt giới hạn dung lượng.")
            except ValueError:
                pass
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise PrivacyError("Trang vượt giới hạn dung lượng.")
            return status, h, data, url
        except OSError as exc:
            raise RuntimeError(f"HTTP proxy connection failed: {type(exc).__name__}; no direct fallback.") from None
        finally:
            conn.close()

    conn = _connect_route(host, port, p.scheme, route, state)
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        status = int(resp.status)
        h = {k.lower(): v for k, v in resp.getheaders()}
        if 300 <= status < 400:
            raise RuntimeError("Redirect bị chặn để tránh route downgrade/SSRF. Hãy xác minh và mở URL đích thủ công.")
        ctype = h.get("content-type", "")
        if not any(x in ctype.lower() for x in ("text/html", "text/plain", "application/json", "application/xhtml+xml")):
            raise PrivacyError("Nội dung không phải HTML/text/JSON; từ chối tải binary.")
        try:
            if int(h.get("content-length", "0") or 0) > max_bytes:
                raise PrivacyError("Trang vượt giới hạn dung lượng.")
        except ValueError:
            pass
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise PrivacyError("Trang vượt giới hạn dung lượng.")
        return status, h, data, url
    finally:
        conn.close()


class _ReaderParser(html.parser.HTMLParser):
    BLOCKED = {"script", "style", "noscript", "svg", "canvas", "iframe", "form", "nav", "footer", "header"}
    BLOCK_TAGS = {"p", "div", "section", "article", "main", "h1", "h2", "h3", "h4", "li", "pre", "blockquote", "br", "tr"}
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.skip = 0; self.title_mode = False; self.title_parts: list[str] = []
        self.parts: list[str] = []; self.links: list[dict[str, str]] = []
        self.current_link: dict[str, str] | None = None
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_d = dict(attrs)
        if tag in self.BLOCKED: self.skip += 1; return
        if self.skip: return
        if tag == "title": self.title_mode = True
        if tag in self.BLOCK_TAGS: self.parts.append("\n")
        if tag == "a" and attrs_d.get("href"):
            self.current_link = {"url": attrs_d["href"] or "", "text": ""}
    def handle_endtag(self, tag: str) -> None:
        if tag in self.BLOCKED:
            self.skip = max(0, self.skip - 1); return
        if self.skip: return
        if tag == "title": self.title_mode = False
        if tag in self.BLOCK_TAGS: self.parts.append("\n")
        if tag == "a" and self.current_link:
            self.links.append(self.current_link); self.current_link = None
    def handle_data(self, data: str) -> None:
        if self.skip: return
        text = re.sub(r"\s+", " ", data).strip()
        if not text: return
        if self.title_mode: self.title_parts.append(text)
        else: self.parts.append(text + " ")
        if self.current_link: self.current_link["text"] += text + " "


class _DDGParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items: list[dict[str, str]] = []; self.current: dict[str, str] | None = None
        self.mode = ""; self.buf: list[str] = []
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs); classes = (a.get("class") or "").split()
        if tag == "a" and "result__a" in classes:
            href = a.get("href") or ""
            q = urllib.parse.urlsplit(href); params = urllib.parse.parse_qs(q.query)
            target = params.get("uddg", [href])[0]
            self.current = {"url": urllib.parse.unquote(target), "title": "", "snippet": ""}; self.mode = "title"; self.buf = []
        elif self.current and tag in {"a", "div"} and "result__snippet" in classes:
            self.mode = "snippet"; self.buf = []
    def handle_data(self, data: str) -> None:
        if self.current and self.mode: self.buf.append(data)
    def handle_endtag(self, tag: str) -> None:
        if self.current and self.mode == "title" and tag == "a":
            self.current["title"] = re.sub(r"\s+", " ", " ".join(self.buf)).strip(); self.mode = ""
        elif self.current and self.mode == "snippet" and tag in {"a", "div"}:
            self.current["snippet"] = re.sub(r"\s+", " ", " ".join(self.buf)).strip(); self.mode = ""
            self.items.append(self.current); self.current = None


def _decode_body(data: bytes, headers: dict[str, str]) -> str:
    charset = "utf-8"
    m = re.search(r"charset\s*=\s*['\"]?([A-Za-z0-9._-]+)", headers.get("content-type", ""), re.I)
    if m:
        charset = m.group(1)
    try: return data.decode(charset, errors="replace")
    except LookupError: return data.decode("utf-8", errors="replace")


def privacy_read(url: str) -> dict[str, Any]:
    state = _snapshot()
    status, headers, data, final_url = _fetch_bytes(url)
    raw = _decode_body(data, headers)
    ctype = headers.get("content-type", "").lower()
    if "html" in ctype or "xhtml" in ctype or raw.lstrip().lower().startswith(("<!doctype html", "<html")):
        parser = _ReaderParser(); parser.feed(raw[:_MAX_PAGE]); parser.close()
        content = re.sub(r"[ \t]+", " ", "\n".join(parser.parts))
        content = re.sub(r"\n\s*\n+", "\n\n", content).strip()[:_MAX_TEXT]
        links = []
        for link in parser.links:
            absolute = urllib.parse.urljoin(final_url, link["url"])
            try:
                lp = _validate_url(absolute, state["route"])
                links.append({"title": re.sub(r"\s+", " ", link["text"]).strip()[:180] or lp.hostname or "link", "url": absolute})
            except Exception:
                continue
            if len(links) >= 60: break
        title = " ".join(parser.title_parts).strip()[:300]
    else:
        title = urllib.parse.urlsplit(final_url).hostname or "Text page"
        content = raw[:_MAX_TEXT]
        links = []
    if status >= 400:
        raise RuntimeError(f"Trang trả HTTP {status}.")
    return {"url": final_url, "title": title, "content": content,
            "links": links, "status": status, "bytes": len(data), "route": state["route"],
            "privacy": "HTML được chuyển thành text; script/style/form/iframe/cookie/cache/download không được chạy hoặc lưu. Không có lịch sử duyệt được ghi xuống đĩa."}


def privacy_search(query: str, provider: str = "duckduckgo") -> dict[str, Any]:
    query = str(query or "").strip()
    if not query or len(query) > 500:
        raise PrivacyError("Query phải có từ 1 đến 500 ký tự.")
    state = _snapshot()
    if provider == "searxng":
        base = state.get("searxng_url")
        if not base:
            raise PrivacyError("Chưa cấu hình SearXNG endpoint trong Privacy Center.")
        url = base + "/search?" + urllib.parse.urlencode({"q": query, "format": "json", "safesearch": 1})
        status, headers, data, _ = _fetch_bytes(url, max_bytes=1_000_000)
        if status >= 400: raise RuntimeError(f"SearXNG trả HTTP {status}. Public instance có thể đã tắt JSON API.")
        try: payload = json.loads(data.decode("utf-8"))
        except Exception: raise RuntimeError("SearXNG không trả JSON hợp lệ; kiểm tra endpoint/format=json.") from None
        rows = []
        for item in payload.get("results", [])[:_MAX_RESULTS]:
            try:
                p = _validate_url(str(item.get("url", "")), state["route"])
                rows.append({"title": str(item.get("title", "Untitled"))[:300], "url": item["url"],
                             "snippet": str(item.get("content", ""))[:700], "domain": p.hostname})
            except Exception: continue
        return {"query": query, "provider": "SearXNG", "route": state["route"], "results": rows,
                "notice": "Search query được gửi tới SearXNG instance đã cấu hình. Kiểm tra chính sách của instance."}
    if provider != "duckduckgo":
        raise PrivacyError("Search provider không hợp lệ.")
    url = "https://html.duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query})
    status, headers, data, _ = _fetch_bytes(url, max_bytes=1_000_000)
    if status >= 400: raise RuntimeError(f"Search provider trả HTTP {status}.")
    parser = _DDGParser(); parser.feed(_decode_body(data, headers)); parser.close()
    rows = []
    for item in parser.items:
        try:
            p = _validate_url(item["url"], state["route"])
            rows.append({"title": item["title"][:300], "url": item["url"], "snippet": item["snippet"][:700], "domain": p.hostname})
        except Exception: continue
        if len(rows) >= _MAX_RESULTS: break
    return {"query": query, "provider": "DuckDuckGo HTML", "route": state["route"], "results": rows,
            "notice": "Query được gửi tới DuckDuckGo. Dùng Tor route hoặc SearXNG instance bạn tin cậy nếu muốn giảm chia sẻ query với search provider."}


def privacy_route_test(acknowledged: bool) -> dict[str, Any]:
    if acknowledged is not True:
        raise PermissionError("Route test gửi request tới dịch vụ kiểm tra IP bên ngoài; cần xác nhận rõ ràng.")
    state = _snapshot(); route = state["route"]
    if route == "tor":
        url = "https://check.torproject.org/api/ip"
        status, headers, data, _ = _fetch_bytes(url, max_bytes=20_000)
        if status >= 400:
            raise RuntimeError(f"Tor Project check API returned HTTP {status}.")
        try:
            payload = json.loads(data.decode("utf-8"))
        except Exception:
            raise RuntimeError("Tor Project check API did not return valid JSON.") from None
        is_tor = payload.get("IsTor") is True
        return {"route": route, "status": "tor-confirmed" if is_tor else "tor-not-confirmed",
                "is_tor": is_tor, "observed_exit_ip": payload.get("IP"),
                "notice": "Tor Project check API xác nhận egress này là Tor." if is_tor else "Tor exit chưa được xác nhận. Không dùng route này như bằng chứng ẩn danh."}
    url = "https://api.ipify.org?format=json"
    status, headers, data, _ = _fetch_bytes(url, max_bytes=20_000)
    if status >= 400:
        raise RuntimeError(f"Egress verification service returned HTTP {status}.")
    try: payload = json.loads(data.decode("utf-8")); ip = payload.get("ip")
    except Exception: ip = data.decode("utf-8", "replace")[:100]
    return {"route": route, "status": "egress-observed", "observed_egress_ip": ip,
            "wireguard": _wireguard_status() if route == "wireguard_system" else None,
            "notice": "Đây chỉ là IP egress mà dịch vụ bên ngoài quan sát được; không chứng minh ẩn danh, DNS kín, không fingerprint hoặc không log."}


def simulate_network(payload: dict[str, Any]) -> dict[str, Any]:
    route = str(payload.get("route", _snapshot()["route"]))
    if route not in {"direct", "tor", "http_proxy", "wireguard_system"}:
        raise PrivacyError("Network profile không hợp lệ.")
    nodes = [{"name": "CyberForge Reader", "type": "application", "mode": "text-only / no cookie"}]
    if route == "direct":
        nodes += [{"name": "Host DNS resolver", "type": "dns", "risk": "DNS query đi theo cấu hình hệ điều hành"},
                  {"name": "ISP / local network", "type": "network"}, {"name": "Destination website", "type": "destination"}]
        risk = "High privacy exposure relative to proxy routes; source IP is visible to destination."
    elif route == "tor":
        nodes += [{"name": "Local Tor SOCKS5", "type": "proxy", "dns": "hostname sent through SOCKS5; remote DNS"},
                  {"name": "Tor entry / relay circuit", "type": "tor"}, {"name": "Tor exit or onion service", "type": "tor"},
                  {"name": "Destination website", "type": "destination"}]
        risk = "Tor reduces source-IP exposure but does not stop account identification, browser fingerprinting, malicious downloads or all traffic outside this app."
    elif route == "http_proxy":
        nodes += [{"name": "Configured HTTP proxy", "type": "proxy"}, {"name": "Destination website", "type": "destination"}]
        risk = "Proxy operator can observe destination metadata and possibly content for plain HTTP. Trust the proxy operator."
    else:
        nodes += [{"name": "Host WireGuard interface", "type": "vpn", "mode": "system-managed"},
                  {"name": "VPN provider / private gateway", "type": "vpn"}, {"name": "Destination website", "type": "destination"}]
        risk = "Simulation assumes host routing uses WireGuard; DNS routing and kill-switch are not verified by the app."
    return {"simulated": True, "route": route, "nodes": nodes, "risk_notes": risk,
            "isolation": {"cookies": "off", "history": "not persisted", "cache": "not persisted", "javascript": "off", "downloads": "off"},
            "notice": "Đây là mô phỏng topology/luồng dữ liệu, không thay đổi interface, firewall, routing table hay DNS trên hệ điều hành."}


def clear_privacy_session() -> dict[str, Any]:
    # No page/search history is retained in this module; resetting route removes proxy secrets.
    with _LOCK:
        _STATE.update({"route": "direct", "tor_host": "127.0.0.1", "tor_port": 9050,
                       "http_proxy": "", "searxng_url": "", "configured_at": None})
    return {"cleared": True, "status": privacy_status(),
            "notice": "Privacy session configuration cleared from memory. This does not erase OS/DNS/router/provider logs or prior external network records."}
