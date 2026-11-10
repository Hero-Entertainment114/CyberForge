"""CyberForge v1.9.1 defensive security engineering helpers.

All analysis is deterministic and local. Traffic labs are mathematical simulations;
no packets, exploit payloads, agents or requests are sent to real systems. Samples
submitted to the static inspector are parsed as data and are never executed.
"""
from __future__ import annotations

import ast
import re
from typing import Any

VERSION = "1.9.1"
MAX_SOURCE_CHARS = 100_000
MAX_HEADERS = 120


def capabilities() -> dict[str, Any]:
    return {
        "version": VERSION,
        "security_advisor": {"mode": "offline-static-analysis", "api_key_required": False,
                             "languages": ["python", "javascript", "typescript", "shell", "generic-config"],
                             "limitations": "Heuristic static analysis; not an LLM, complete SAST, DAST or proof of exploitability."},
        "web_posture": {"mode": "user-supplied-headers-and-cookies", "network_io": False,
                        "checks": ["HSTS", "CSP", "CORS", "cookies", "COOP/COEP/CORP", "referrer", "permissions", "information-disclosure"]},
        "defense_lab": {"mode": "bounded-discrete-time-simulation", "network_io": False,
                        "max_agents": 200, "max_duration_seconds": 120},
        "privacy": {"mode": "user-supplied-exposure-hints", "device_scanning": False,
                    "guarantees_anonymity": False},
        "sandbox": {"mode": "static-only", "executes_samples": False,
                    "malware_detonation": False},
    }


def _text(value: Any, field: str = "source", limit: int = MAX_SOURCE_CHARS) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} phải là văn bản.")
    if len(value) > limit:
        raise ValueError(f"{field} vượt giới hạn {limit} ký tự.")
    return value


def _int(value: Any, field: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{field} phải là số nguyên trong khoảng {low}..{high}.")
    return value


def _safe_evidence(evidence: str) -> str:
    value = evidence[:220]
    value = re.sub(r"(?i)(api[_-]?key|client_secret|password|passwd|token)\s*[:=]\s*(['\"])[^'\"]+\2",
                   r"\1=[REDACTED]", value)
    value = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", value)
    return value


def _finding(rule: str, line: int, severity: str, confidence: str, cwe: str,
             title: str, evidence: str, recommendation: str) -> dict[str, Any]:
    return {"rule": rule, "line": max(0, int(line)), "severity": severity,
            "confidence": confidence, "cwe": cwe, "title": title,
            "evidence": _safe_evidence(evidence), "recommendation": recommendation}


def secure_code_review(source: str, language: str = "auto") -> dict[str, Any]:
    """Small, explainable multi-language security review; read-only, no code execution."""
    source = _text(source)
    language = (language or "auto").strip().lower()
    allowed = {"auto", "python", "javascript", "typescript", "shell", "generic"}
    if language not in allowed:
        raise ValueError("Ngôn ngữ không được hỗ trợ.")
    if language == "auto":
        if re.search(r"\b(def|import|from|async def)\b", source) and not re.search(r"\b(const|let|function)\b", source):
            language = "python"
        elif re.search(r"\b(const|let|function|require\s*\()", source):
            language = "javascript"
        else:
            language = "generic"

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    def add(rule: str, line: int, severity: str, confidence: str, cwe: str,
            title: str, evidence: str, advice: str) -> None:
        key = (rule, line)
        if key not in seen:
            seen.add(key)
            findings.append(_finding(rule, line, severity, confidence, cwe, title, evidence, advice))

    lines = source.splitlines()
    if language == "python":
        try:
            tree = ast.parse(source or "\n")
        except SyntaxError as exc:
            add("syntax-error", exc.lineno or 1, "info", "high", "N/A",
                "Python syntax error", exc.msg, "Sửa lỗi cú pháp trước khi chạy các kiểm tra tiếp theo.")
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                owner = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else ""
                line = getattr(node, "lineno", 1)
                segment = lines[line - 1].strip() if 0 < line <= len(lines) else name
                if name in {"eval", "exec"}:
                    add("dynamic-evaluation", line, "high", "high", "CWE-95", "Dynamic code evaluation", segment,
                        "Tránh eval/exec với dữ liệu bên ngoài; thay bằng parser hoặc dispatch qua allowlist.")
                elif name in {"loads", "load"} and owner in {"pickle", "yaml", "marshal", "dill", "shelve"}:
                    safe_yaml_loader = owner == "yaml" and any(
                        kw.arg == "Loader" and isinstance(kw.value, ast.Attribute) and kw.value.attr in {"SafeLoader", "CSafeLoader"}
                        for kw in node.keywords)
                    if not safe_yaml_loader:
                        add("unsafe-deserialization", line, "high", "medium", "CWE-502", "Potentially unsafe deserialization", segment,
                            "Không giải tuần tự dữ liệu không tin cậy bằng pickle/dill/marshal hoặc YAML loader không an toàn; dùng safe loader, định dạng dữ liệu an toàn và schema validation.")
                elif name in {"system", "popen"} and owner == "os":
                    add("shell-command", line, "high", "high", "CWE-78", "Shell command execution", segment,
                        "Ưu tiên subprocess với argv cố định, shell=False, allowlist và timeout; không nối đầu vào người dùng vào lệnh.")
                elif owner == "subprocess" and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                    add("subprocess-shell-true", line, "high", "high", "CWE-78", "subprocess called with shell=True", segment,
                        "Dùng danh sách đối số và shell=False; xác thực đường dẫn và giới hạn thời gian chạy.")
                elif name in {"get", "post", "put", "request"} and owner in {"requests", "httpx"} and any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords):
                    add("tls-verification-disabled", line, "high", "high", "CWE-295", "TLS certificate verification disabled", segment,
                        "Bật xác minh chứng chỉ TLS; cấu hình CA tin cậy thay vì tắt verify.")
                elif name in {"md5", "sha1"} and owner == "hashlib":
                    add("legacy-hash", line, "medium", "high", "CWE-328", "Legacy hash algorithm", segment,
                        "Dùng SHA-256/ SHA-3 cho integrity; dùng Argon2id/bcrypt/scrypt cho mật khẩu.")
    patterns: list[tuple[str, str, str, str, str, str, str]] = []
    if language in {"javascript", "typescript", "generic"}:
        patterns.extend([
            ("dynamic-evaluation", r"\beval\s*\(|\bnew\s+Function\s*\(", "high", "CWE-95", "Dynamic code evaluation", "Tránh eval/new Function với dữ liệu không tin cậy; dùng parser hoặc logic tĩnh."),
            ("unsafe-dom-sink", r"\.innerHTML\s*=|document\.write\s*\(", "high", "CWE-79", "Potential unsafe DOM injection sink", "Dùng textContent hoặc sanitizer theo allowlist; kiểm tra ngữ cảnh HTML/URL/JS."),
            ("shell-command", r"child_process\.(exec|execSync)\s*\(", "high", "CWE-78", "Shell command execution candidate", "Ưu tiên execFile/spawn với argv cố định, shell:false và allowlist."),
            ("weak-random", r"Math\.random\s*\(.*(?:token|secret|nonce|session)", "medium", "CWE-330", "Weak randomness may be used for a security value", "Dùng crypto.randomUUID hoặc crypto.getRandomValues cho token và nonce."),
        ])
    if language in {"shell", "generic"}:
        patterns.extend([
            ("shell-eval", r"\beval\s+['\"]?\$|\beval\s+\$", "high", "CWE-95", "Shell eval of variable content", "Tránh eval dữ liệu động; dùng case/allowlist và truyền tham số như dữ liệu."),
            ("remote-script-pipe", r"\b(curl|wget)\b[^\n|]*\|\s*(sh|bash)\b", "high", "CWE-494", "Remote content piped directly to a shell", "Tải về để xác minh nguồn, chữ ký/hash và đọc nội dung trước khi thực thi."),
        ])
    patterns.extend([
        ("hardcoded-secret", r"(?i)\b(api[_-]?key|client_secret|password|passwd|token)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]", "high", "CWE-798", "Possible hard-coded secret", "Chuyển secret sang secret manager hoặc biến môi trường; xoay vòng credential nếu đã commit."),
        ("wildcard-cors", r"(?i)(access-control-allow-origin\s*[:=]\s*['\"]\*|allow_origins\s*=\s*\[\s*['\"]\*['\"])", "medium", "CWE-942", "Wildcard CORS policy", "Chỉ cho phép origin cụ thể; không kết hợp wildcard với credential."),
        ("debug-production", r"(?i)\b(debug|development)\s*[:=]\s*(true|1)", "medium", "CWE-489", "Debug/development mode may be enabled", "Tắt debug trong môi trường production và bảo vệ endpoint quản trị."),
        ("tls-verification-disabled", r"(?i)(verify\s*=\s*false|cert_none|rejectUnauthorized\s*:\s*false)", "high", "CWE-295", "TLS verification appears disabled", "Bật xác minh TLS và cài CA hợp lệ; không bỏ qua lỗi chứng chỉ trong production."),
        ("sql-concatenation", r"(?i)(select|insert|update|delete).{0,140}(\+\s*\w+|\$\{[^}]+\}|\.format\s*\()", "medium", "CWE-89", "Possible SQL string construction", "Dùng prepared/parameterized statements; không nội suy dữ liệu người dùng vào câu SQL."),
    ])
    for rule, pattern, severity, cwe, title, advice in patterns:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                confidence = "high" if rule in {"hardcoded-secret", "tls-verification-disabled", "dynamic-evaluation", "unsafe-dom-sink"} else "medium"
                add(rule, i, severity, confidence, cwe, title, line.strip(), advice)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: (order.get(x["severity"], 9), x["line"], x["rule"]))
    counts = {key: sum(1 for item in findings if item["severity"] == key) for key in ("critical", "high", "medium", "low", "info")}
    return {"engine": "CyberForge Offline Security Advisor 1.9.1", "mode": "static-only",
            "language": language, "source_lines": len(lines), "findings": findings,
            "severity_counts": counts, "findings_count": len(findings),
            "summary": f"Tìm thấy {len(findings)} dấu hiệu cần xem xét trong {len(lines)} dòng." if findings else "Không phát hiện mẫu rủi ro trong bộ luật hiện có.",
            "next_steps": ["Xác minh từng finding trong ngữ cảnh ứng dụng.", "Ưu tiên high/critical trước khi phát hành.",
                           "Chạy scanner chuyên dụng và test thủ công; heuristic có thể bỏ sót hoặc báo nhầm."],
            "limitations": "Không thực thi source, không kiểm chứng exploitability, không thay thế SAST/DAST/LLM hoặc review thủ công."}


def web_posture_review(headers: dict[str, Any], cookies: list[str] | None = None) -> dict[str, Any]:
    if not isinstance(headers, dict) or len(headers) > MAX_HEADERS:
        raise ValueError(f"Headers phải là object tối đa {MAX_HEADERS} mục.")
    if cookies is not None and (not isinstance(cookies, list) or len(cookies) > 40):
        raise ValueError("Cookies phải là danh sách tối đa 40 mục.")
    h = {str(k).strip().lower(): str(v)[:4000] for k, v in headers.items()}
    findings: list[dict[str, Any]] = []
    def add(rule: str, severity: str, title: str, recommendation: str, evidence: str = "") -> None:
        findings.append({"rule": rule, "severity": severity, "title": title,
                         "recommendation": recommendation, "evidence": evidence[:300]})
    hsts = h.get("strict-transport-security", "")
    if not hsts:
        add("hsts-missing", "high", "HSTS header is missing", "Enable HSTS after confirming all affected hosts serve HTTPS.")
    elif not re.search(r"max-age\s*=\s*(\d+)", hsts, re.I) or int(re.search(r"max-age\s*=\s*(\d+)", hsts, re.I).group(1)) < 15_552_000:
        add("hsts-short-max-age", "medium", "HSTS max-age is absent or shorter than six months", "Use a reviewed max-age; do not enable includeSubDomains/preload until every subdomain is HTTPS.", hsts)
    csp = h.get("content-security-policy", "")
    if not csp:
        add("csp-missing", "high", "Content-Security-Policy is missing", "Create a report-only policy, tune it, then enforce a nonce/hash-based CSP.")
    else:
        if re.search(r"'unsafe-inline'|'unsafe-eval'", csp, re.I):
            add("csp-unsafe-source", "medium", "CSP allows unsafe inline/eval sources", "Replace unsafe sources with nonces/hashes and remove eval where possible.", csp)
        if re.search(r"(?:default-src|script-src)\s+[^;]*\*", csp, re.I):
            add("csp-wildcard", "high", "CSP contains a wildcard source", "Restrict source expressions to trusted origins.", csp)
        if not re.search(r"(?:^|;)\s*object-src\s+", csp, re.I):
            add("csp-object-src", "low", "CSP does not explicitly restrict object-src", "Consider object-src 'none' unless legacy embeds are required.", csp)
    if h.get("x-content-type-options", "").lower() != "nosniff":
        add("nosniff-missing", "medium", "X-Content-Type-Options is missing or weak", "Set X-Content-Type-Options: nosniff.", h.get("x-content-type-options", ""))
    frame_policy = h.get("x-frame-options", "").lower()
    if not frame_policy in {"deny", "sameorigin"} and not re.search(r"frame-ancestors\s+[^;]+", csp, re.I):
        add("frame-protection-missing", "medium", "No effective frame embedding policy was detected", "Use CSP frame-ancestors; retain X-Frame-Options for legacy clients.")
    ref = h.get("referrer-policy", "").lower()
    if ref not in {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}:
        add("referrer-policy-weak", "low", "Referrer-Policy is absent or permissive", "Choose strict-origin-when-cross-origin or no-referrer.", ref)
    if not h.get("permissions-policy"):
        add("permissions-policy-missing", "low", "Permissions-Policy is missing", "Disable browser capabilities that the application does not use.")
    if not h.get("cross-origin-opener-policy"):
        add("coop-missing", "low", "Cross-Origin-Opener-Policy is missing", "Consider same-origin where compatible with popup and OAuth flows.")
    if not h.get("cross-origin-embedder-policy"):
        add("coep-missing", "info", "Cross-Origin-Embedder-Policy is missing", "Use require-corp/credentialless only when cross-origin resource requirements are understood.")
    if not h.get("cross-origin-resource-policy"):
        add("corp-missing", "info", "Cross-Origin-Resource-Policy is missing", "Set an appropriate same-site/same-origin policy for resources that should not be embedded cross-origin.")
    cors_origin = h.get("access-control-allow-origin", "").strip()
    cors_credentials = h.get("access-control-allow-credentials", "").strip().lower() == "true"
    if cors_origin == "*" and cors_credentials:
        add("cors-wildcard-credentials", "critical", "Wildcard CORS and credentials are both enabled", "Use an explicit origin allowlist; browsers reject this combination but intermediaries and policy mistakes remain risky.")
    elif cors_origin == "*":
        add("cors-wildcard", "medium", "CORS allows every origin", "Restrict to trusted origins if the resource is not intentionally public.")
    if h.get("server") or h.get("x-powered-by"):
        add("server-banner", "low", "Server technology banner is exposed", "Remove unnecessary product/version banners; this is defense-in-depth only.", "; ".join(f"{k}: {h[k]}" for k in ("server", "x-powered-by") if h.get(k)))
    cookie_values = list(cookies or [])
    if h.get("set-cookie"):
        cookie_values.extend([item.strip() for item in h["set-cookie"].split("\n") if item.strip()])
    for cookie in cookie_values:
        c = str(cookie)[:3000]
        name = c.split("=", 1)[0].strip()[:100]
        attrs = c.split(";")[1:]
        safe_cookie = (name + "=<redacted>; " + "; ".join(x.strip() for x in attrs))[:300]
        if not re.search(r"(?:^|;)\s*secure\s*(?:;|$)", c, re.I):
            add("cookie-secure", "high", f"Cookie {name or '(unnamed)'} lacks Secure", "Set Secure on cookies used over HTTPS.", safe_cookie)
        if not re.search(r"(?:^|;)\s*httponly\s*(?:;|$)", c, re.I):
            add("cookie-httponly", "medium", f"Cookie {name or '(unnamed)'} lacks HttpOnly", "Set HttpOnly unless client-side JavaScript access is explicitly required.", safe_cookie)
        if not re.search(r"(?:^|;)\s*samesite\s*=\s*(strict|lax|none)", c, re.I):
            add("cookie-samesite", "medium", f"Cookie {name or '(unnamed)'} lacks SameSite", "Choose SameSite=Lax/Strict; use None only with Secure when cross-site use is required.", safe_cookie)
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda x: (-ranks[x["severity"]], x["rule"]))
    weighted = sum(ranks[x["severity"]] for x in findings)
    score = max(0, 100 - min(100, weighted * 5))
    return {"mode": "user-supplied-header-review", "network_io": False, "score": score,
            "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D",
            "checks": 12 + len(cookies or []), "findings": findings, "findings_count": len(findings),
            "note": "Only supplied headers/cookies are evaluated. No HTTP request is sent; a missing header is not proof of exploitability."}


def simulate_defense_scenario(legitimate_rps: int = 80, agents: int = 50,
                              events_per_agent_rps: int = 30, capacity_rps: int = 1000,
                              duration_seconds: int = 30, rate_limit_per_agent: int = 5,
                              cache_percent: int = 20, queue_limit: int = 2000,
                              challenge_filter_percent: int = 0) -> dict[str, Any]:
    """Discrete-time defensive model with synthetic events only; no network IO."""
    legitimate_rps = _int(legitimate_rps, "legitimate_rps", 0, 10_000)
    agents = _int(agents, "agents", 0, 200)
    events_per_agent_rps = _int(events_per_agent_rps, "events_per_agent_rps", 0, 1_000)
    capacity_rps = _int(capacity_rps, "capacity_rps", 1, 100_000)
    duration_seconds = _int(duration_seconds, "duration_seconds", 1, 120)
    rate_limit_per_agent = _int(rate_limit_per_agent, "rate_limit_per_agent", 0, 1_000)
    cache_percent = _int(cache_percent, "cache_percent", 0, 95)
    queue_limit = _int(queue_limit, "queue_limit", 1, 50_000)
    challenge_filter_percent = _int(challenge_filter_percent, "challenge_filter_percent", 0, 100)
    if agents * events_per_agent_rps * duration_seconds > 24_000_000:
        raise ValueError("Tổng sự kiện mô phỏng vượt giới hạn 24 triệu.")

    legit_queue = 0.0
    bot_queue = 0.0
    totals = {"legitimate_in": 0, "bot_in": 0, "bot_rate_limited": 0,
              "bot_challenged": 0, "legitimate_cache_served": 0,
              "bot_cache_served": 0, "legitimate_origin_served": 0,
              "bot_origin_served": 0, "legitimate_dropped": 0, "bot_dropped": 0}
    queue_samples: list[float] = []
    cache_ratio = cache_percent / 100.0
    challenge_ratio = challenge_filter_percent / 100.0
    for _second in range(duration_seconds):
        legit = legitimate_rps
        raw_bot = agents * events_per_agent_rps
        limited_bot = min(events_per_agent_rps, rate_limit_per_agent) * agents
        filtered_rate = raw_bot - limited_bot
        challenged = int(limited_bot * challenge_ratio)
        forwarded_bot = limited_bot - challenged
        legit_cache = int(legit * cache_ratio)
        bot_cache = int(forwarded_bot * cache_ratio)
        legit_origin = legit - legit_cache
        bot_origin = forwarded_bot - bot_cache
        legit_queue += legit_origin
        bot_queue += bot_origin
        # Bound queued work; discard bot backlog first, preserving legitimate traffic.
        overflow = max(0.0, legit_queue + bot_queue - queue_limit)
        bot_drop_queue = min(bot_queue, overflow)
        bot_queue -= bot_drop_queue
        overflow -= bot_drop_queue
        legit_drop_queue = min(legit_queue, overflow)
        legit_queue -= legit_drop_queue
        service = capacity_rps
        legit_served = min(legit_queue, service)
        legit_queue -= legit_served
        service -= legit_served
        bot_served = min(bot_queue, service)
        bot_queue -= bot_served
        totals["legitimate_in"] += legit
        totals["bot_in"] += raw_bot
        totals["bot_rate_limited"] += filtered_rate
        totals["bot_challenged"] += challenged
        totals["legitimate_cache_served"] += legit_cache
        totals["bot_cache_served"] += bot_cache
        totals["legitimate_origin_served"] += int(legit_served)
        totals["bot_origin_served"] += int(bot_served)
        totals["legitimate_dropped"] += int(legit_drop_queue)
        totals["bot_dropped"] += int(bot_drop_queue)
        queue_samples.append(legit_queue + bot_queue)
    legit_total = totals["legitimate_in"]
    legit_served_total = totals["legitimate_cache_served"] + totals["legitimate_origin_served"]
    legit_ratio = legit_served_total / legit_total if legit_total else 1.0
    ordered = sorted(queue_samples)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * .95))] if ordered else 0
    return {"mode": "synthetic-defense-simulation", "network_io": False,
            "duration_seconds": duration_seconds, "configuration": {
                "legitimate_rps": legitimate_rps, "virtual_agents": agents,
                "events_per_agent_rps": events_per_agent_rps, "capacity_rps": capacity_rps,
                "rate_limit_per_agent": rate_limit_per_agent, "cache_percent": cache_percent,
                "queue_limit": queue_limit, "challenge_filter_percent": challenge_filter_percent},
            "totals": totals, "pending_at_end": {"legitimate": round(legit_queue, 1), "bot": round(bot_queue, 1)},
            "estimated_legitimate_availability": round(legit_ratio, 4),
            "estimated_legitimate_served_rps": round(legit_served_total / duration_seconds, 2),
            "estimated_queue_p95": round(p95, 1),
            "recommendations": ["Áp dụng rate-limit theo tài khoản/session/API key và IP; tránh chỉ dựa IP khi có NAT.",
                                "Giới hạn queue, timeout, concurrency và dùng back-pressure.",
                                "Cache dữ liệu công khai, áp dụng challenge/risk scoring theo hành vi.",
                                "Theo dõi p95/p99 latency, 429/5xx, queue depth, CPU, RAM và upstream saturation."],
            "limitations": "Mô hình rời rạc đơn giản, không mô phỏng giao thức, phân phối địa lý, TCP, CDN hoặc hành vi bot thật; không dùng để dự báo SLA chính xác."}


def privacy_posture_audit(user_agent: str = "", headers: dict[str, Any] | None = None,
                          environment_hints: dict[str, Any] | None = None) -> dict[str, Any]:
    user_agent = _text(user_agent, "user_agent", 2048)
    if headers is not None and not isinstance(headers, dict):
        raise ValueError("headers phải là object.")
    if environment_hints is not None and not isinstance(environment_hints, dict):
        raise ValueError("environment_hints phải là object.")
    if len(headers or {}) > 80 or len(environment_hints or {}) > 40:
        raise ValueError("Quá nhiều privacy signals.")
    hdr = {str(k).lower(): str(v)[:1000] for k, v in (headers or {}).items()}
    hints = {str(k): str(v)[:300] for k, v in (environment_hints or {}).items()}
    signals = []
    if user_agent:
        if re.search(r"Windows NT|Mac OS X|Linux|Android|iPhone", user_agent, re.I):
            signals.append({"signal": "platform-in-user-agent", "risk": "medium", "detail": "User-Agent tiết lộ họ nền tảng."})
        if re.search(r"Chrome/|Firefox/|Edg/|Version/", user_agent):
            signals.append({"signal": "browser-version", "risk": "low", "detail": "User-Agent tiết lộ họ trình duyệt/phiên bản."})
    for key in ("x-forwarded-for", "x-real-ip", "forwarded", "via"):
        if key in hdr:
            signals.append({"signal": "routing-header", "risk": "high", "detail": f"Header {key} có thể tiết lộ thông tin mạng."})
    hint_keys = {"timezone", "language", "screen", "platform", "hardware_concurrency", "device_memory", "webgl_vendor", "webgl_renderer"}
    provided = sorted(set(k.lower() for k in hints) & hint_keys)
    if len(provided) >= 3:
        signals.append({"signal": "combined-fingerprint-hints", "risk": "medium", "detail": f"Có {len(provided)} nhóm hint có thể kết hợp để phân biệt trình duyệt."})
    if "accept-language" in hdr:
        signals.append({"signal": "language-preference", "risk": "low", "detail": "Accept-Language tiết lộ sở thích ngôn ngữ."})
    return {"mode": "local-user-supplied-exposure-audit", "network_io": False,
            "signals": signals, "signal_count": len(signals), "provided_hint_categories": provided,
            "recommendations": ["Giảm các header và browser hints không cần thiết, nhưng giữ tương thích website.",
                                "Chặn third-party tracking/cookies bằng trình duyệt có bảo vệ quyền riêng tư.",
                                "Không đưa định danh hoặc dữ liệu nhạy cảm vào URL/log.",
                                "Dùng Tor/VPN phù hợp với mô hình đe dọa; chúng không xóa dấu vết ở endpoint."],
            "guarantee": "Không có chế độ nào đảm bảo ẩn danh tuyệt đối. Audit này chỉ phân tích tín hiệu do người dùng cung cấp; không quét thiết bị hay thay đổi network stack."}


def static_sandbox_triage(source: str, language: str = "auto") -> dict[str, Any]:
    source = _text(source, limit=50_000)
    language = (language or "auto").strip().lower()
    if language not in {"auto", "python", "javascript", "typescript", "shell", "powershell", "php", "generic"}:
        raise ValueError("Ngôn ngữ không được hỗ trợ.")
    review_language = language if language in {"auto", "python", "javascript", "typescript", "shell", "generic"} else "generic"
    result = secure_code_review(source, review_language)
    extra = []
    patterns = [
        ("persistence-hint", r"(?i)(RunOnce|CurrentVersion\\Run|crontab|systemctl\s+enable|LaunchAgents)", "medium", "Persistence-related string; validate context."),
        ("credential-access-hint", r"(?i)(Login Data|id_rsa|\.ssh/|SAM\\\\|SECURITY\\\\|wallet\.dat)", "high", "Potential credential or sensitive-store reference."),
        ("defense-evasion-hint", r"(?i)(AMSI|ETW|DisableRealtimeMonitoring|wevtutil\s+cl)", "high", "Potential defense-evasion string; a string alone does not prove behavior."),
        ("network-download-hint", r"(?i)(https?://|socket\.connect|DownloadString|Invoke-WebRequest)", "low", "Network/download-related indicator; inspect surrounding code."),
    ]
    for rule, pattern, severity, title in patterns:
        for line_no, line in enumerate(source.splitlines(), 1):
            if re.search(pattern, line):
                extra.append({"rule": rule, "line": line_no, "severity": severity,
                              "title": title, "evidence": line.strip()[:180]})
    return {"mode": "static-only", "executed": False, "language": language if language != "auto" else result["language"],
            "findings": result["findings"], "sample_indicators": extra,
            "findings_count": len(result["findings"]) + len(extra),
            "summary": f"{len(result['findings'])} code findings and {len(extra)} contextual indicators.",
            "notice": "Không thực thi, giải nén, load DLL, import module hoặc mở kết nối. Kết quả chỉ là dấu hiệu phục vụ triage, không phải verdict malware."}
