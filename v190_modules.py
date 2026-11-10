"""CyberForge v1.9.0 safe lab and offline assistant primitives.

All traffic simulations are mathematical/local-only. No network packets are sent.
Sandbox inspection is static; submitted code is never executed by this module.
"""
from __future__ import annotations
import ast, re, time
from collections import Counter
from typing import Any

VERSION = "1.9.0"

def capabilities() -> dict[str, Any]:
    return {
        "version": VERSION,
        "ai": {"mode": "offline-rules", "api_key_optional": True,
               "note": "Offline heuristic assistant; external model adapters require user configuration."},
        "sandbox": {"mode": "static-inspection", "executes_samples": False,
                    "note": "No sample execution. OS-level isolation is not claimed."},
        "traffic_lab": {"mode": "mathematical-simulation", "network_io": False,
                        "max_virtual_agents": 200, "max_requests": 50000},
        "privacy": {"mode": "local-exposure-audit", "guarantees_anonymity": False},
    }

def _bounded_text(value: Any, limit: int = 100_000) -> str:
    if not isinstance(value, str):
        raise ValueError("Dữ liệu phải là văn bản.")
    if len(value) > limit:
        raise ValueError(f"Văn bản vượt giới hạn {limit} ký tự.")
    return value

def ai_security_advice(source: str, task: str = "review") -> dict[str, Any]:
    source = _bounded_text(source)
    rules = [
        ("possible-hardcoded-secret", r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "Có dấu hiệu bí mật được hard-code. Chuyển sang biến môi trường hoặc secret manager."),
        ("sql-string-concatenation", r"(?i)(select|insert|update|delete).{0,100}(\+|%s|\.format\()", "Có thể ghép chuỗi SQL. Dùng truy vấn tham số hóa."),
        ("dynamic-eval", r"\b(eval|exec)\s*\(", "Hàm thực thi động làm tăng rủi ro injection. Tránh dùng hoặc giới hạn đầu vào."),
        ("disabled-tls-validation", r"(?i)(verify\s*=\s*False|CERT_NONE)", "Đang tắt xác minh TLS. Bật xác minh chứng chỉ."),
        ("wildcard-cors", r"(?i)(Access-Control-Allow-Origin\s*[:=]\s*['\"]\*|allow_origins\s*=\s*\[\s*['\"]\*\s*['\"])", "CORS wildcard có thể mở rộng bề mặt truy cập. Giới hạn origin."),
        ("debug-enabled", r"(?i)(debug\s*=\s*True|DEBUG\s*=\s*True)", "Không bật debug trong production."),
        ("weak-hash", r"\b(md5|sha1)\s*\(", "MD5/SHA-1 không phù hợp cho mật khẩu/chữ ký mới. Dùng Argon2id/bcrypt hoặc SHA-256 theo mục đích."),
        ("shell-injection-risk", r"(shell\s*=\s*True|os\.system\s*\()", "Có nguy cơ shell injection. Dùng subprocess với danh sách đối số cố định."),
    ]
    findings=[]
    for rule, pattern, advice in rules:
        if re.search(pattern, source):
            findings.append({"rule":rule,"severity":"high" if rule in {"possible-hardcoded-secret","shell-injection-risk","dynamic-eval"} else "medium","advice":advice})
    return {"engine":"CyberForge Offline Security Advisor","task":task[:80],"findings":findings,
            "summary":f"Phát hiện {len(findings)} dấu hiệu cần xem xét." if findings else "Không phát hiện mẫu rủi ro phổ biến trong bộ luật cơ bản.",
            "limitations":"Đây là phân tích heuristic, không thay thế SAST/DAST chuyên dụng hoặc kiểm thử thủ công."}

def simulate_capacity(requests: int = 10000, capacity_per_second: int = 500,
                      duration_seconds: int = 10, legitimate_rate: int = 40) -> dict[str, Any]:
    vals=(requests,capacity_per_second,duration_seconds,legitimate_rate)
    if any(type(v) is not int for v in vals): raise ValueError("Các tham số phải là số nguyên.")
    if not 1 <= requests <= 50000 or not 1 <= capacity_per_second <= 100000 or not 1 <= duration_seconds <= 300 or not 0 <= legitimate_rate <= 10000:
        raise ValueError("Tham số mô phỏng nằm ngoài giới hạn an toàn.")
    offered=requests/duration_seconds
    capacity=capacity_per_second
    served=min(offered,capacity)
    legit_served=min(legitimate_rate, max(0, capacity - max(0, offered-legitimate_rate)))
    return {"mode":"synthetic-capacity-model","network_io":False,"offered_rps":round(offered,2),
            "capacity_rps":capacity,"estimated_served_rps":round(served,2),
            "estimated_dropped_rps":round(max(0,offered-served),2),
            "legitimate_rps":legitimate_rate,"estimated_legitimate_served_rps":round(legit_served,2),
            "availability_ratio":round(served/offered,4) if offered else 1.0,
            "recommendations":["Rate limiting theo IP/tài khoản và route","Queue có giới hạn, timeout và back-pressure",
             "Cache nội dung tĩnh, CDN/WAF và autoscaling có ngưỡng","Theo dõi p95/p99 latency, error rate và saturation"]}

def simulate_virtual_fleet(agents: int = 50, requests_each: int = 100,
                           capacity_rps: int = 500) -> dict[str, Any]:
    if any(type(v) is not int for v in (agents,requests_each,capacity_rps)): raise ValueError("Tham số phải là số nguyên.")
    if not 1 <= agents <= 200 or not 1 <= requests_each <= 10000 or not 1 <= capacity_rps <= 100000:
        raise ValueError("Giới hạn: 1-200 tác nhân ảo, 1-10000 lượt/tác nhân.")
    total=agents*requests_each
    return {"mode":"virtual-agent-emulation","agents":agents,"requests_per_agent":requests_each,
            "synthetic_total_events":total,"capacity_rps":capacity_rps,"network_io":False,
            "note":"Tác nhân chỉ tạo sự kiện giả lập trong bộ nhớ; không kết nối, lây nhiễm hay điều khiển thiết bị thật.",
            "defense_checks":["Phát hiện burst bất thường","Giới hạn tốc độ theo danh tính và nguồn","Circuit breaker","Phân biệt bot hợp lệ và hành vi tự động bất thường"]}

def web_hardening_review(headers: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(headers,dict) or len(headers)>100: raise ValueError("Headers phải là object tối đa 100 mục.")
    normalized={str(k).lower():str(v)[:2000] for k,v in headers.items()}
    checks=[
      ("strict-transport-security","strict-transport-security","Bật HSTS trên HTTPS sau khi xác nhận toàn bộ subdomain hỗ trợ HTTPS."),
      ("content-security-policy","content-security-policy","Thiết lập CSP theo nonce/hash; tránh unsafe-inline nếu có thể."),
      ("x-content-type-options","x-content-type-options","Đặt X-Content-Type-Options: nosniff."),
      ("frame-protection","x-frame-options","Dùng frame-ancestors trong CSP hoặc X-Frame-Options."),
      ("referrer-policy","referrer-policy","Thiết lập Referrer-Policy nghiêm ngặt."),
      ("permissions-policy","permissions-policy","Giới hạn camera, microphone, geolocation theo nhu cầu."),
    ]
    missing=[{"id":i,"header":h,"recommendation":a} for i,h,a in checks if h not in normalized]
    return {"checks":len(checks),"missing":missing,"score":round((len(checks)-len(missing))/len(checks)*100),
            "note":"Đánh giá dựa trên header do người dùng cung cấp; chưa thực hiện request tới website."}

def privacy_exposure_audit(user_agent: str = "", headers: dict[str, Any] | None = None) -> dict[str, Any]:
    ua=_bounded_text(user_agent,2048)
    hdr=headers if isinstance(headers,dict) else {}
    signals=[]
    if ua and re.search(r"(Windows NT|Mac OS X|Linux|Android|iPhone)",ua,re.I):
        signals.append("User-Agent tiết lộ họ hệ điều hành/thiết bị.")
    if ua and re.search(r"Chrome/|Firefox/|Edg/|Version/",ua):
        signals.append("User-Agent tiết lộ họ trình duyệt và phiên bản.")
    for key in hdr:
        if str(key).lower() in {"x-forwarded-for","x-real-ip","via","forwarded"}:
            signals.append(f"Header {key} có thể tiết lộ thông tin định tuyến/IP.")
    return {"signals":signals,"signal_count":len(signals),
            "recommendations":["Không giả mạo danh tính hoặc xóa dấu vết kiểm toán để né tránh truy cứu.",
             "Giảm thông tin User-Agent ở tầng ứng dụng nếu tương thích.",
             "Dùng trình duyệt có bảo vệ chống tracking, chặn third-party cookies.",
             "Không gửi dữ liệu nhạy cảm trong URL; rà soát log và telemetry."],
            "guarantee":"Không có chế độ nào đảm bảo ẩn danh tuyệt đối; website, ISP, hệ điều hành và mạng vẫn có thể nhận diện."}

def sandbox_static_inspect(source: str, language: str = "python") -> dict[str, Any]:
    source=_bounded_text(source,50000)
    findings=[]
    if language.lower()=="python":
        try:
            tree=ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Exec,)) if hasattr(ast,"Exec") else False: pass
                if isinstance(node, ast.Call):
                    name=(node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else "")
                    if name in {"eval","exec","compile","__import__","system","popen"}:
                        findings.append({"line":getattr(node,"lineno",0),"risk":"dynamic-or-process-execution","symbol":name})
                    if name in {"urlopen","requests","connect","send"}:
                        findings.append({"line":getattr(node,"lineno",0),"risk":"network-capability","symbol":name})
        except SyntaxError as e:
            findings.append({"line":e.lineno or 0,"risk":"syntax-error","symbol":e.msg})
    else:
        for line_no,line in enumerate(source.splitlines(),1):
            if re.search(r"\b(eval|exec|system|popen|curl|wget)\b",line,re.I):
                findings.append({"line":line_no,"risk":"suspicious-command-pattern","symbol":line.strip()[:120]})
    return {"mode":"static-only","executed":False,"language":language,"findings":findings,
            "summary":f"{len(findings)} dấu hiệu cần xem xét."}
