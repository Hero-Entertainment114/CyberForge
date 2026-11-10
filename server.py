#!/usr/bin/env python3
"""CyberForge Server Edition v2.1.0 - Linux-first control plane."""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import os
import shutil
import subprocess
import platform
import ipaddress
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

import integrations
import connectors
import security_ops
import security_intelligence
import threat_intel
import detection_engine
from server_core import APP_NAME, AIService, Store, host_inventory, run_workflow, utc_now, VERSION
from distributed import create_store, EnvelopeCipher
from ai_control import AIControlPlane, gpu_inventory, scheduler_config

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("CF_SERVER_DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
MAX_BODY = 256 * 1024

ERROR_MESSAGES = {
    "en": {
        "ai_paid_requires_explicit_selection": "Select a paid model explicitly. Paid deployments are never selected automatically.", "ai_queue_full": "The AI job queue is full. Retry shortly.", "ai_job_not_found": "AI job not found.", "ai_job_failed": "The AI job failed.", "ai_model_disabled": "The selected AI deployment is disabled.", "ai_deployment_disabled": "The requested AI deployment is disabled.", "ai_scheduler_stopped": "The AI scheduler is shutting down and did not start this job.", "ai_no_healthy_deployment": "No healthy eligible AI deployment is available.", "ai_model_concurrency_timeout": "The selected model remained at its concurrency limit for too long.", "invalid_job_priority": "Job priority must be high, normal or low.", "invalid_route_strategy": "Route strategy must be auto or pinned.", "invalid_model_policy": "Model policy values are outside the permitted range.", "paid_model_cannot_be_default": "A paid deployment cannot be selected as the automatic default.", "disabled_model_cannot_be_default": "A disabled deployment cannot be selected as the automatic default.",
        "invalid_host_header": "The Host header is not allowlisted.", "proxy_only": "Remote clients must connect from an IP/CIDR listed in CF_SERVER_TRUST_PROXY_CIDRS.",
        "connector_test_not_supported": "This integration has no active health-check adapter yet.",
        "connector_endpoint_not_configured": "The connector endpoint is not configured.", "connector_invalid_endpoint": "The connector endpoint is invalid.",
        "connector_host_not_allowlisted": "The connector host is not in CF_CONNECTOR_ALLOWED_HOSTS.",
        "connector_remote_requires_https": "Remote connector endpoints must use HTTPS.", "connector_credentials_missing": "Required connector credentials are missing from the environment.",
        "connector_unreachable": "The connector endpoint could not be reached.",
        "unauthorized": "Authentication required or token invalid.", "forbidden": "You do not have permission for this operation.",
        "not_found": "The requested resource was not found.", "invalid_json": "The request body is not valid JSON.",
        "body_too_large": "The request body exceeds the allowed size.", "invalid_request": "The request is invalid.", "invalid_ai_deployments_json": "AI deployment configuration is invalid JSON or exceeds its limit.",
        "invalid_ai_deployment_id": "AI deployment ID is invalid or duplicated.", "invalid_ai_key_env": "AI API-key environment variable name is invalid.",
        "ai_deployment_not_found": "The requested AI deployment is not configured.", "invalid_temperature": "Temperature must be between 0 and 2.",
        "node_auth_failed": "Node authentication failed.", "replayed_node_request": "The node report was already received.",
        "ai_model_not_configured": "No AI model is configured. Set CF_AI_MODEL and the endpoint variables.",
        "ai_provider_unreachable": "The AI provider could not be reached.", "ai_provider_http_error": "The AI provider returned an HTTP error.",
        "ai_provider_invalid_response": "The AI provider returned an invalid response.", "paid_ai_not_enabled": "Paid AI is disabled. Enable it explicitly before use.",
        "paid_ai_budget_not_configured": "Paid AI requires a daily budget and token prices.",
        "ai_daily_budget_exceeded": "The daily AI budget would be exceeded.", "ai_request_budget_exceeded": "The estimated request cost exceeds the per-request limit.",
        "ai_endpoint_host_not_allowlisted": "The AI endpoint host is not in the server allowlist.", "remote_ai_requires_https": "Remote AI endpoints must use HTTPS.",
        "workflow_not_found": "Workflow not found.", "workflow_not_approved": "Workflow has not been approved.",
        "workflow_expired": "Workflow approval expired.", "workflow_step_not_allowed": "This workflow step is not allowed.",
        "two_person_approval_required": "A different operator must approve this workflow.", "node_timestamp_out_of_range": "Node timestamp is outside the permitted time window.",
        "invalid_messages": "The AI message list is invalid.", "prompt_too_large": "The AI prompt is too large.",
        "security_source_not_supported": "This security telemetry source is not supported.", "security_event_invalid": "A security event is invalid.", "security_batch_invalid": "The event batch must contain between 1 and 100 events.", "security_batch_too_large": "The normalized event batch exceeds the allowed limit.", "security_invalid_status": "The incident status is invalid.", "security_invalid_severity": "The incident severity is invalid.", "security_invalid_assignee": "The assignee is invalid.", "security_incident_not_found": "The incident was not found.", "security_playbook_not_found": "The playbook run was not found.", "security_playbook_not_allowed": "The requested playbook is not allowed.", "security_playbook_not_pending": "The playbook run is not awaiting approval.", "security_playbook_not_approved": "The playbook run is not approved.", "security_playbook_expired": "The playbook approval has expired.", "security_two_person_approval_required": "A different user must approve this playbook.", "security_playbook_step_not_allowed": "The playbook step is not allowed.",
        "security_correlation_invalid_window": "Correlation window must be between 1 and 240 minutes.",
        "security_ai_analysis_unavailable": "The incident evidence could not be prepared for AI analysis.",
        "threat_ioc_invalid": "The indicator value is invalid for the selected type.", "threat_ioc_type_unsupported": "This indicator type is not supported.",
        "threat_ioc_batch_invalid": "The indicator batch must contain between 1 and 100 items.", "threat_ioc_not_found": "No matching indicator was found.",
        "threat_feed_not_found": "The threat intelligence feed was not found.", "threat_feed_invalid": "The feed name or configuration is invalid.",
        "threat_feed_type_unsupported": "This feed type is not supported.", "threat_feed_type_mismatch": "The submitted data does not match this feed type.",
        "threat_feed_disabled": "The threat intelligence feed is disabled.", "threat_feed_url_invalid": "The feed URL is invalid.",
        "threat_feed_https_required": "Remote threat feeds must use HTTPS.", "threat_feed_host_not_allowlisted": "The feed host is not in CF_THREAT_INTEL_ALLOWED_HOSTS.",
        "threat_feed_url_not_used": "This feed type accepts uploaded data and does not fetch a URL.",
        "threat_feed_auth_env_invalid": "The authentication environment variable name is invalid.", "threat_feed_credentials_missing": "The configured feed credential is missing.",
        "threat_feed_redirect_rejected": "Remote feed redirects are not followed.", "threat_feed_http_error": "The threat feed returned an HTTP error.",
        "threat_feed_unreachable": "The threat feed could not be reached.", "threat_feed_too_large": "The threat feed exceeds the allowed response size.",
        "threat_feed_format_invalid": "The threat feed response format is invalid.", "threat_feed_sync_failed": "The threat feed synchronization failed.",
        "threat_feed_manual_import_only": "This feed type requires a manual data import.", "threat_stix_bundle_invalid": "The STIX bundle is invalid.",
        "threat_stix_object_limit": "The STIX bundle exceeds the object limit.", "threat_taxii_no_api_root": "The TAXII discovery response contains no API root.",
        "threat_taxii_collection_required": "Select a TAXII collection ID when the server exposes multiple collections.",
        "threat_taxii_collection_not_found": "The configured TAXII collection was not found.", "threat_taxii_cross_host_rejected": "The TAXII API root must use the same allowlisted host.",
        "threat_taxii_object_limit": "The TAXII object response exceeds the allowed limit.", "threat_epss_batch_invalid": "Provide between 1 and 50 valid CVE identifiers.",
        "threat_epss_response_invalid": "FIRST EPSS returned an invalid response.",
        "detection_rule_invalid": "The detection rule definition is invalid.",
        "detection_rule_condition_required": "At least one condition is required.",
        "detection_rule_too_large": "The detection rule exceeds the size limit.",
        "detection_rule_invalid_attack_id": "One or more MITRE ATT&CK technique IDs are invalid.",
        "detection_rule_not_found": "The detection rule was not found.",
        "detection_rule_not_valid": "Validate the current rule version before publishing or testing it.",
        "detection_two_person_publish_required": "A different authorized API actor must publish this rule. Token names are not proof of separate human identities.",
        "detection_rule_invalid_version": "The detection rule version is invalid.",
        "detection_rule_rollback_target_invalid": "Rollback target must be a previously published version.",
        "detection_rule_invalid_state": "The requested detection rule state is invalid.",
        "internal_error": "The server could not complete the request.",
    },
    "vi": {
        "ai_paid_requires_explicit_selection": "Hãy chọn rõ model trả phí. Deployment trả phí không bao giờ được tự động chọn.", "ai_queue_full": "Hàng đợi AI đang đầy. Vui lòng thử lại sau.", "ai_job_not_found": "Không tìm thấy tác vụ AI.", "ai_job_failed": "Tác vụ AI thất bại.", "ai_model_disabled": "Deployment AI được chọn đang bị tắt.", "ai_deployment_disabled": "Deployment AI được yêu cầu hiện đang bị tắt.", "ai_scheduler_stopped": "Bộ lập lịch AI đang dừng nên không khởi chạy tác vụ này.", "ai_no_healthy_deployment": "Không có deployment AI phù hợp đang khỏe mạnh.", "ai_model_concurrency_timeout": "Model đã ở giới hạn đồng thời quá lâu.", "invalid_job_priority": "Độ ưu tiên phải là high, normal hoặc low.", "invalid_route_strategy": "Chiến lược định tuyến phải là auto hoặc pinned.", "invalid_model_policy": "Giá trị chính sách model nằm ngoài giới hạn cho phép.", "paid_model_cannot_be_default": "Không thể đặt deployment trả phí làm model mặc định tự động.", "disabled_model_cannot_be_default": "Không thể đặt deployment đang tắt làm model mặc định.",
        "invalid_host_header": "Host trong HTTP header chưa được cho phép.", "proxy_only": "Kết nối từ xa phải đến từ IP/CIDR được khai báo trong CF_SERVER_TRUST_PROXY_CIDRS.",
        "connector_test_not_supported": "Tích hợp này chưa có adapter kiểm tra kết nối.",
        "connector_endpoint_not_configured": "Chưa cấu hình endpoint cho connector.", "connector_invalid_endpoint": "Endpoint connector không hợp lệ.",
        "connector_host_not_allowlisted": "Host connector chưa nằm trong CF_CONNECTOR_ALLOWED_HOSTS.",
        "connector_remote_requires_https": "Endpoint connector từ xa bắt buộc sử dụng HTTPS.", "connector_credentials_missing": "Thiếu thông tin xác thực connector trong biến môi trường.",
        "connector_unreachable": "Không thể kết nối tới endpoint connector.",
        "unauthorized": "Yêu cầu đăng nhập hoặc token không hợp lệ.", "forbidden": "Bạn không có quyền thực hiện thao tác này.",
        "not_found": "Không tìm thấy tài nguyên được yêu cầu.", "invalid_json": "Dữ liệu yêu cầu không phải JSON hợp lệ.",
        "body_too_large": "Dung lượng nội dung yêu cầu vượt giới hạn.", "invalid_request": "Yêu cầu không hợp lệ.", "invalid_ai_deployments_json": "Cấu hình deployment AI không phải JSON hợp lệ hoặc vượt giới hạn.",
        "invalid_ai_deployment_id": "ID deployment AI không hợp lệ hoặc bị trùng.", "invalid_ai_key_env": "Tên biến môi trường chứa API key không hợp lệ.",
        "ai_deployment_not_found": "Deployment AI được yêu cầu chưa được cấu hình.", "invalid_temperature": "Temperature phải nằm trong khoảng từ 0 đến 2.",
        "node_auth_failed": "Xác thực node thất bại.", "replayed_node_request": "Báo cáo node này đã được nhận trước đó.",
        "ai_model_not_configured": "Chưa cấu hình model AI. Hãy thiết lập CF_AI_MODEL và các biến endpoint.",
        "ai_provider_unreachable": "Không thể kết nối tới nhà cung cấp AI.", "ai_provider_http_error": "Nhà cung cấp AI trả về lỗi HTTP.",
        "ai_provider_invalid_response": "Nhà cung cấp AI trả về dữ liệu không hợp lệ.", "paid_ai_not_enabled": "AI trả phí đang bị tắt. Hãy chủ động bật trước khi sử dụng.",
        "paid_ai_budget_not_configured": "AI trả phí cần giới hạn ngân sách ngày và đơn giá token.",
        "ai_daily_budget_exceeded": "Yêu cầu sẽ vượt ngân sách AI trong ngày.", "ai_request_budget_exceeded": "Chi phí ước tính vượt giới hạn cho mỗi yêu cầu.",
        "ai_endpoint_host_not_allowlisted": "Máy chủ AI chưa nằm trong danh sách host được cho phép.", "remote_ai_requires_https": "Endpoint AI từ xa bắt buộc sử dụng HTTPS.",
        "workflow_not_found": "Không tìm thấy quy trình.", "workflow_not_approved": "Quy trình chưa được phê duyệt.",
        "workflow_expired": "Phê duyệt quy trình đã hết hạn.", "workflow_step_not_allowed": "Bước quy trình này không được cho phép.",
        "two_person_approval_required": "Một người vận hành khác phải phê duyệt quy trình này.", "node_timestamp_out_of_range": "Thời gian báo cáo node nằm ngoài cửa sổ cho phép.",
        "invalid_messages": "Danh sách tin nhắn AI không hợp lệ.", "prompt_too_large": "Prompt AI vượt quá kích thước cho phép.",
        "security_source_not_supported": "Nguồn telemetry bảo mật này chưa được hỗ trợ.", "security_event_invalid": "Sự kiện bảo mật không hợp lệ.", "security_batch_invalid": "Lô sự kiện phải chứa từ 1 đến 100 sự kiện.", "security_batch_too_large": "Lô sự kiện sau chuẩn hóa vượt giới hạn cho phép.", "security_invalid_status": "Trạng thái incident không hợp lệ.", "security_invalid_severity": "Mức độ nghiêm trọng không hợp lệ.", "security_invalid_assignee": "Người được giao xử lý không hợp lệ.", "security_incident_not_found": "Không tìm thấy incident.", "security_playbook_not_found": "Không tìm thấy lượt chạy playbook.", "security_playbook_not_allowed": "Playbook được yêu cầu không nằm trong danh sách cho phép.", "security_playbook_not_pending": "Playbook không ở trạng thái chờ phê duyệt.", "security_playbook_not_approved": "Playbook chưa được phê duyệt.", "security_playbook_expired": "Phê duyệt playbook đã hết hạn.", "security_two_person_approval_required": "Một người dùng khác phải phê duyệt playbook.", "security_playbook_step_not_allowed": "Bước playbook không được cho phép.",
        "security_correlation_invalid_window": "Cửa sổ tương quan phải nằm trong khoảng 1 đến 240 phút.",
        "security_ai_analysis_unavailable": "Không thể chuẩn bị bằng chứng sự cố để phân tích bằng AI.",
        "threat_ioc_invalid": "Giá trị IOC không hợp lệ với loại chỉ báo đã chọn.", "threat_ioc_type_unsupported": "Loại chỉ báo này chưa được hỗ trợ.",
        "threat_ioc_batch_invalid": "Lô IOC phải chứa từ 1 đến 100 mục.", "threat_ioc_not_found": "Không tìm thấy IOC khớp.",
        "threat_feed_not_found": "Không tìm thấy nguồn threat intelligence.", "threat_feed_invalid": "Tên hoặc cấu hình nguồn dữ liệu không hợp lệ.",
        "threat_feed_type_unsupported": "Loại nguồn dữ liệu này chưa được hỗ trợ.", "threat_feed_type_mismatch": "Dữ liệu gửi lên không khớp với loại nguồn đã chọn.",
        "threat_feed_disabled": "Nguồn threat intelligence đang bị tắt.", "threat_feed_url_invalid": "URL nguồn dữ liệu không hợp lệ.",
        "threat_feed_https_required": "Nguồn threat intelligence từ xa bắt buộc sử dụng HTTPS.", "threat_feed_host_not_allowlisted": "Host của nguồn dữ liệu chưa nằm trong CF_THREAT_INTEL_ALLOWED_HOSTS.",
        "threat_feed_url_not_used": "Loại nguồn này nhận dữ liệu tải lên và không truy cập URL.",
        "threat_feed_auth_env_invalid": "Tên biến môi trường xác thực không hợp lệ.", "threat_feed_credentials_missing": "Thiếu thông tin xác thực nguồn dữ liệu đã cấu hình.",
        "threat_feed_redirect_rejected": "CyberForge không đi theo chuyển hướng của nguồn dữ liệu.", "threat_feed_http_error": "Nguồn threat feed trả về lỗi HTTP.",
        "threat_feed_unreachable": "Không thể kết nối tới nguồn threat feed.", "threat_feed_too_large": "Phản hồi threat feed vượt dung lượng cho phép.",
        "threat_feed_format_invalid": "Định dạng phản hồi threat feed không hợp lệ.", "threat_feed_sync_failed": "Đồng bộ threat feed thất bại.",
        "threat_feed_manual_import_only": "Loại feed này yêu cầu nhập dữ liệu thủ công.", "threat_stix_bundle_invalid": "STIX bundle không hợp lệ.",
        "threat_stix_object_limit": "STIX bundle vượt giới hạn số object.", "threat_taxii_no_api_root": "Phản hồi discovery TAXII không có API root.",
        "threat_taxii_collection_required": "Hãy chọn collection ID khi máy chủ TAXII cung cấp nhiều collection.",
        "threat_taxii_collection_not_found": "Không tìm thấy TAXII collection đã cấu hình.", "threat_taxii_cross_host_rejected": "TAXII API root phải sử dụng cùng host đã được cho phép.",
        "threat_taxii_object_limit": "Phản hồi TAXII vượt giới hạn object.", "threat_epss_batch_invalid": "Hãy cung cấp từ 1 đến 50 CVE hợp lệ.",
        "threat_epss_response_invalid": "FIRST EPSS trả về dữ liệu không hợp lệ.",
        "detection_rule_invalid": "Định nghĩa quy tắc phát hiện không hợp lệ.",
        "detection_rule_condition_required": "Cần có ít nhất một điều kiện.",
        "detection_rule_too_large": "Quy tắc phát hiện vượt quá giới hạn dung lượng.",
        "detection_rule_invalid_attack_id": "Một hoặc nhiều mã kỹ thuật MITRE ATT&CK không hợp lệ.",
        "detection_rule_not_found": "Không tìm thấy quy tắc phát hiện.",
        "detection_rule_not_valid": "Hãy kiểm tra tính hợp lệ của phiên bản hiện tại trước khi thử hoặc phát hành.",
        "detection_two_person_publish_required": "Một danh tính tác nhân API được ủy quyền khác phải phát hành quy tắc. Tên token không chứng minh hai người khác nhau.",
        "detection_rule_invalid_version": "Phiên bản quy tắc phát hiện không hợp lệ.",
        "detection_rule_rollback_target_invalid": "Phiên bản khôi phục phải là một phiên bản đã được phát hành trước đó.",
        "detection_rule_invalid_state": "Trạng thái quy tắc phát hiện được yêu cầu không hợp lệ.",
        "internal_error": "Máy chủ không thể hoàn tất yêu cầu.",
    },
}


def is_allowed_bind_address(bind: str, allow_private: bool = False) -> bool:
    """Loopback is default; private numeric IPs require an explicit opt-in."""
    if bind in {"127.0.0.1", "::1", "localhost"}:
        return True
    if not allow_private:
        return False
    try:
        address = ipaddress.ip_address(bind)
    except ValueError:
        return False
    return bool(address.is_private and not (address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast))


def configured_proxy_networks():
    networks = []
    for raw in os.getenv("CF_SERVER_TRUST_PROXY_CIDRS", "").split(","):
        value = raw.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError("invalid_proxy_cidr") from exc
    return networks


def is_trusted_proxy_client(client_ip: str) -> bool:
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    if getattr(address, "ipv4_mapped", None):
        address = address.ipv4_mapped
    if address.is_loopback:
        return True
    if os.getenv("CF_SERVER_TRUST_PROXY", "0") != "1":
        return False
    try:
        return any(address in network for network in configured_proxy_networks())
    except ValueError:
        return False


def _json_safe(value):
    return json.loads(json.dumps(value, default=str))


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server with a hard cap on concurrently served requests."""
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, server_address, RequestHandlerClass, max_concurrency: int = 64):
        self.max_concurrency = max(4, min(512, int(max_concurrency)))
        self._capacity = threading.BoundedSemaphore(self.max_concurrency)
        super().__init__(server_address, RequestHandlerClass)

    def process_request(self, request, client_address):
        if not self._capacity.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\nRetry-After: 2\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._capacity.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._capacity.release()


def create_handler(store: Store, ai: AIService, data_dir: Path, ai_control: AIControlPlane | None = None):
    ai_control = ai_control or AIControlPlane(store, ai)
    security_ops.initialize(store)
    threat_intel.initialize(store)
    class Handler(BaseHTTPRequestHandler):
        server_version = "CyberForgeServer/" + VERSION
        sys_version = ""

        def log_message(self, fmt, *args):
            if os.getenv("CF_SERVER_ACCESS_LOG", "0") == "1":
                super().log_message(fmt, *args)

        def _headers(self, content_type="application/json; charset=utf-8", length=None):
            self.send_header("Content-Type", content_type)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            if length is not None:
                self.send_header("Content-Length", str(length))

        def _send(self, status: int, obj, content_type="application/json; charset=utf-8"):
            raw = obj.encode("utf-8") if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self._headers(content_type, len(raw))
            self.end_headers()
            self.wfile.write(raw)

        def _error(self, status: int, code: str, detail: str | None = None):
            locale = "vi" if self.headers.get("Accept-Language", "").lower().startswith("vi") else "en"
            message = ERROR_MESSAGES.get(locale, ERROR_MESSAGES["en"]).get(code, ERROR_MESSAGES["en"].get(code, "Request failed."))
            payload = {"ok": False, "error": {"code": code, "message": message}}
            if detail:
                payload["error"]["detail"] = detail[:500]
            self._send(status, payload)

        def _body(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ValueError("invalid_request")
            if length < 0 or length > MAX_BODY:
                raise OverflowError("body_too_large")
            raw = self.rfile.read(length) if length else b"{}"
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("invalid_json") from exc
            if not isinstance(obj, dict):
                raise ValueError("invalid_json")
            return obj

        def _check_host(self):
            raw = self.headers.get("Host", "")
            try:
                host = urlsplit("//" + raw).hostname or ""
            except ValueError:
                host = ""
            defaults = {"127.0.0.1", "localhost", "::1"}
            configured = {x.strip().lower() for x in os.getenv("CF_SERVER_ALLOWED_HOSTS", "").split(",") if x.strip()}
            if host.lower() not in defaults | configured:
                raise PermissionError("invalid_host_header")
            if not is_trusted_proxy_client(self.client_address[0]):
                raise PermissionError("proxy_only")

        def _actor(self, scope: str | None = None):
            value = self.headers.get("Authorization", "")
            if not value.startswith("Bearer "):
                raise PermissionError("unauthorized")
            actor = store.authenticate(value[7:].strip())
            if not actor:
                raise PermissionError("unauthorized")
            if scope and not Store.has_scope(actor, scope):
                raise PermissionError("forbidden")
            return actor

        def do_GET(self):
            path = urlsplit(self.path).path
            try:
                self._check_host()
            except PermissionError:
                self._error(421, "invalid_host_header")
                return
            if path == "/":
                try:
                    raw = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
                    self._send(200, raw, "text/html; charset=utf-8")
                except OSError:
                    self._error(500, "internal_error")
                return
            if path == "/api/v200/health":
                self._send(200, {"ok": True, "product": "CyberForge Server Edition", "version": VERSION, "time": utc_now()})
                return
            try:
                if path == "/api/v200/overview":
                    actor = self._actor("fleet:read")
                    nodes = store.list_nodes()
                    host = host_inventory(data_dir)
                    self._send(200, {"version": VERSION, "host": host,
                                     "fleet": {"total": len(nodes), "online": sum(n["status"] == "online" for n in nodes),
                                                "stale": sum(n["status"] == "stale" for n in nodes), "pending": sum(n["status"] == "pending" for n in nodes)},
                                     "integrations": integrations.catalog_summary(), "ai": ai.status(),
                                     "audit": store.verify_audit(), "actor": {"name": actor["name"], "role": actor["role"]}})
                elif path == "/api/v200/nodes":
                    self._actor("fleet:read")
                    self._send(200, {"nodes": store.list_nodes()})
                elif path == "/api/v200/integrations":
                    self._actor("integrations:read")
                    items = integrations.inventory()
                    for item in items:
                        item["test_supported"] = connectors.test_supported(item["id"])
                    self._send(200, {"summary": integrations.catalog_summary(), "items": items})
                elif path == "/api/v200/ai/status":
                    self._actor("integrations:read")
                    self._send(200, ai.status())
                elif path == "/api/v201/ai/models":
                    self._actor("ai:models:read")
                    self._send(200, {"models": ai_control.models()})
                elif path == "/api/v201/ai/queue":
                    self._actor("ai:jobs:read")
                    self._send(200, ai_control.queue_status())
                elif path == "/api/v201/ai/gpu":
                    self._actor("system:read")
                    self._send(200, gpu_inventory())
                elif path == "/api/v202/cluster":
                    self._actor("system:read")
                    self._send(200, ai_control.cluster_status())
                elif path.startswith("/api/v201/ai/jobs/"):
                    actor = self._actor("ai:jobs:read")
                    job_id = path.rsplit("/", 1)[-1]
                    job = ai_control.get_job(job_id, actor)
                    if job.get("error_code"):
                        locale = "vi" if self.headers.get("Accept-Language", "").lower().startswith("vi") else "en"
                        job["error_message"] = ERROR_MESSAGES.get(locale, ERROR_MESSAGES["en"]).get(
                            job["error_code"], ERROR_MESSAGES[locale].get("ai_job_failed", "AI job failed."))
                    self._send(200, job)
                elif path in {"/api/v203/security/sources", "/api/v204/security/sources"}:
                    self._actor("security:read")
                    api_prefix = "/api/v204" if path.startswith("/api/v204/") else "/api/v203"
                    self._send(200, {"sources": [{"id": x, "ingest_path": f"{api_prefix}/security/ingest/{x}"} for x in security_ops.SOURCES]})
                elif path == "/api/v204/security/mitre/summary":
                    self._actor("security:analysis")
                    self._send(200, security_intelligence.mitre_coverage(store))
                elif path.startswith("/api/v204/security/incidents/") and path.endswith("/analysis"):
                    self._actor("security:analysis")
                    incident_id = path.split("/")[-2]
                    query = parse_qs(urlsplit(self.path).query)
                    window = int((query.get("window_minutes") or [30])[0])
                    self._send(200, security_intelligence.incident_analysis(store, incident_id, window_minutes=window))
                elif path == "/api/v210/detection/overview":
                    self._actor("detection:read")
                    self._send(200, detection_engine.summary(store))
                elif path == "/api/v210/detection/rules":
                    self._actor("detection:read")
                    query = parse_qs(urlsplit(self.path).query)
                    self._send(200, {"rules": detection_engine.list_rules(store,
                        state=(query.get("state") or [None])[0], limit=int((query.get("limit") or [100])[0]))})
                elif path == "/api/v210/detection/matches":
                    self._actor("detection:read")
                    query = parse_qs(urlsplit(self.path).query)
                    self._send(200, {"matches": detection_engine.list_matches(store, limit=int((query.get("limit") or [100])[0]))})
                elif path.startswith("/api/v210/detection/rules/"):
                    self._actor("detection:read")
                    rule_id = path.rsplit("/", 1)[-1]
                    self._send(200, {"rule": detection_engine.get_rule(store, rule_id)})
                elif path == "/api/v205/threat-intel/overview":
                    self._actor("threatintel:read")
                    self._send(200, threat_intel.summary(store))
                elif path == "/api/v205/threat-intel/feeds":
                    self._actor("threatintel:read")
                    self._send(200, {"feeds": threat_intel.list_feeds(store)})
                elif path == "/api/v205/threat-intel/iocs":
                    self._actor("threatintel:read")
                    query = parse_qs(urlsplit(self.path).query)
                    self._send(200, {"iocs": threat_intel.list_iocs(store, ioc_type=(query.get("type") or [None])[0], limit=int((query.get("limit") or [100])[0]))})
                elif path == "/api/v205/threat-intel/lookup":
                    self._actor("threatintel:read")
                    query = parse_qs(urlsplit(self.path).query)
                    self._send(200, threat_intel.lookup(store, (query.get("type") or [""])[0], (query.get("value") or [""])[0]))
                elif path.startswith("/api/v205/threat-intel/incidents/") and path.endswith("/enrichment"):
                    self._actor("threatintel:read")
                    incident_id = path.split("/")[-2]
                    self._send(200, threat_intel.enrich_incident(store, incident_id))
                elif path == "/api/v203/security/overview":
                    self._actor("security:read")
                    self._send(200, security_ops.overview(store))
                elif path == "/api/v203/security/incidents":
                    self._actor("security:read")
                    query = parse_qs(urlsplit(self.path).query)
                    self._send(200, {"incidents": security_ops.list_incidents(store,
                        status=(query.get("status") or [None])[0], severity=(query.get("severity") or [None])[0],
                        limit=int((query.get("limit") or [100])[0]))})
                elif path == "/api/v203/security/events":
                    self._actor("security:read")
                    query = parse_qs(urlsplit(self.path).query)
                    self._send(200, {"events": security_ops.list_events(store,
                        source=(query.get("source") or [None])[0], severity=(query.get("severity") or [None])[0],
                        limit=int((query.get("limit") or [100])[0]))})
                elif path.startswith("/api/v203/security/incidents/") and "/" not in path[len("/api/v203/security/incidents/"):]:
                    self._actor("security:read")
                    incident_id = path.rsplit("/", 1)[-1]
                    self._send(200, security_ops.incident_detail(store, incident_id))
                elif path == "/api/v203/security/playbooks":
                    self._actor("security:read")
                    self._send(200, {"playbooks": security_ops.list_playbooks(), "runs": security_ops.list_playbook_runs(store)})
                elif path == "/api/v200/workflows":
                    self._actor("workflows:read")
                    self._send(200, {"workflows": store.list_workflows()})
                elif path == "/api/v200/audit":
                    actor = self._actor("audit:read")
                    self._send(200, {"events": store.audit_events(), "verification": store.verify_audit()})
                elif path == "/api/v200/system":
                    self._actor("system:read")
                    self._send(200, {"host": host_inventory(data_dir), "data_dir": str(data_dir),
                                     "python": sys.version.split()[0], "pid": os.getpid(), "uptime_seconds": int(time.monotonic() - STARTED)})
                elif path == "/metrics":
                    self._actor("metrics:read")
                    nodes = store.list_nodes()
                    lines = ["# HELP cyberforge_nodes_total Registered nodes", "# TYPE cyberforge_nodes_total gauge",
                             f"cyberforge_nodes_total {len(nodes)}", "# HELP cyberforge_nodes_online Online nodes", "# TYPE cyberforge_nodes_online gauge",
                             f"cyberforge_nodes_online {sum(n['status'] == 'online' for n in nodes)}"]
                    lines += ["# HELP cyberforge_audit_events_total Audit events", "# TYPE cyberforge_audit_events_total gauge",
                              f"cyberforge_audit_events_total {store.verify_audit()['events_checked']}"]
                    try:
                        sec = security_ops.overview(store)
                        lines += ["# HELP cyberforge_security_incidents_total Security incidents", "# TYPE cyberforge_security_incidents_total gauge",
                                  f"cyberforge_security_incidents_total {sec['incidents_total']}",
                                  "# HELP cyberforge_security_events_total Normalized security events", "# TYPE cyberforge_security_events_total gauge",
                                  f"cyberforge_security_events_total {sec['events_total']}"]
                        det = detection_engine.summary(store)
                        lines += ["# HELP cyberforge_detection_rules_published Published detection rules", "# TYPE cyberforge_detection_rules_published gauge",
                                  f"cyberforge_detection_rules_published {det['published_rules']}",
                                  "# HELP cyberforge_detection_matches_total Detection rule matches", "# TYPE cyberforge_detection_matches_total gauge",
                                  f"cyberforge_detection_matches_total {det['matches_total']}"]
                    except Exception:
                        pass
                    self._send(200, "\n".join(lines) + "\n", "text/plain; version=0.0.4; charset=utf-8")
                else:
                    self._error(404, "not_found")
            except KeyError as exc:
                code = str(exc).strip("'\"")
                self._error(404, code if code in ERROR_MESSAGES["en"] else "not_found")
            except PermissionError as exc:
                code = str(exc)
                known = code if code in ERROR_MESSAGES["en"] else ("unauthorized" if code == "unauthorized" else "forbidden")
                self._error(401 if known == "unauthorized" else 403, known)
            except (ValueError, TypeError) as exc:
                code = str(exc)
                known = code if code in ERROR_MESSAGES["en"] else "invalid_request"
                self._error(400, known)
            except Exception:
                self._error(500, "internal_error")

        def do_POST(self):
            path = urlsplit(self.path).path
            try:
                self._check_host()
            except PermissionError:
                self._error(421, "invalid_host_header")
                return
            try:
                body = self._body()
            except OverflowError:
                self._error(413, "body_too_large")
                return
            except ValueError as exc:
                self._error(400, str(exc) if str(exc) in {"invalid_json", "invalid_request"} else "invalid_json")
                return
            try:
                if path == "/api/v210/detection/rules":
                    actor = self._actor("detection:manage")
                    result = detection_engine.create_draft(store, body, actor["name"])
                    self._send(201, {"ok": True, "rule": result})
                elif path.startswith("/api/v210/detection/rules/") and path.endswith("/draft"):
                    actor = self._actor("detection:manage")
                    rule_id = path.split("/")[-2]
                    result = detection_engine.revise_draft(store, rule_id, body, actor["name"])
                    self._send(201, {"ok": True, "rule": result})
                elif path.startswith("/api/v210/detection/rules/") and path.endswith("/validate"):
                    actor = self._actor("detection:manage")
                    rule_id = path.split("/")[-2]
                    self._send(200, {"ok": True, "validation": detection_engine.validate_rule(store, rule_id, actor["name"])})
                elif path.startswith("/api/v210/detection/rules/") and path.endswith("/test"):
                    actor = self._actor("detection:manage")
                    rule_id = path.split("/")[-2]
                    self._send(200, {"ok": True, "test": detection_engine.test_rule(store, rule_id, actor["name"], body.get("limit", 250))})
                elif path.startswith("/api/v210/detection/rules/") and path.endswith("/publish"):
                    actor = self._actor("detection:publish")
                    rule_id = path.split("/")[-2]
                    self._send(200, {"ok": True, "rule": detection_engine.publish_rule(store, rule_id, actor["name"])})
                elif path.startswith("/api/v210/detection/rules/") and path.endswith("/retire"):
                    actor = self._actor("detection:publish")
                    rule_id = path.split("/")[-2]
                    self._send(200, {"ok": True, "rule": detection_engine.retire_rule(store, rule_id, actor["name"])})
                elif path.startswith("/api/v210/detection/rules/") and path.endswith("/rollback"):
                    actor = self._actor("detection:publish")
                    rule_id = path.split("/")[-2]
                    self._send(201, {"ok": True, "rule": detection_engine.rollback_to_version(store, rule_id, body.get("target_version"), actor["name"])})
                elif path == "/api/v205/threat-intel/feeds":
                    actor = self._actor("threatintel:manage")
                    result = threat_intel.create_feed(store, body, actor["name"])
                    self._send(201, {"ok": True, "feed": result})
                elif path.startswith("/api/v205/threat-intel/feeds/") and path.endswith("/sync"):
                    actor = self._actor("threatintel:manage")
                    feed_id = path.split("/")[-2]
                    self._send(200, {"ok": True, "result": threat_intel.sync_feed(store, feed_id, actor["name"])})
                elif path.startswith("/api/v205/threat-intel/feeds/") and path.endswith("/enable"):
                    actor = self._actor("threatintel:manage")
                    feed_id = path.split("/")[-2]
                    self._send(200, {"ok": True, "feed": threat_intel.set_feed_enabled(store, feed_id, body.get("enabled", False), actor["name"])})
                elif path == "/api/v205/threat-intel/import/stix":
                    actor = self._actor("threatintel:manage")
                    result = threat_intel.import_stix(store, str(body.get("feed_id", "")), body.get("bundle"), actor["name"])
                    self._send(202, {"ok": True, "result": result})
                elif path == "/api/v205/threat-intel/import/json":
                    actor = self._actor("threatintel:manage")
                    result = threat_intel.import_json_iocs(store, str(body.get("feed_id", "")), body.get("indicators"), actor["name"])
                    self._send(202, {"ok": True, "result": result})
                elif path == "/api/v205/threat-intel/lookup/batch":
                    self._actor("threatintel:enrich")
                    self._send(200, {"results": threat_intel.lookup_many(store, body.get("indicators"))})
                elif path == "/api/v205/threat-intel/epss/lookup":
                    self._actor("threatintel:enrich")
                    self._send(200, threat_intel.epss_lookup(body.get("cves"), store))
                elif path.startswith("/api/v204/security/ingest/"):
                    actor = self._actor("security:ingest")
                    source = path.rsplit("/", 1)[-1]
                    items = body.get("events") if isinstance(body.get("events"), list) else [body.get("event", body)]
                    result = security_ops.ingest(store, source, items, actor["name"])
                    self._send(202, {"ok": True, "result": result})
                elif path.startswith("/api/v204/security/incidents/") and path.endswith("/correlate"):
                    actor = self._actor("security:correlate")
                    incident_id = path.split("/")[-2]
                    result = security_intelligence.correlate_incident(store, incident_id,
                        window_minutes=body.get("window_minutes", 30), actor=actor["name"], persist=True)
                    self._send(200, {"ok": True, "correlation": result})
                elif path.startswith("/api/v204/security/incidents/") and path.endswith("/ai-analysis"):
                    actor = self._actor("ai:invoke")
                    if not Store.has_scope(actor, "security:analysis"):
                        raise PermissionError("forbidden")
                    incident_id = path.split("/")[-2]
                    analysis = security_intelligence.incident_analysis(store, incident_id,
                        window_minutes=body.get("window_minutes", 30))
                    analysis["threat_intelligence"] = threat_intel.enrich_incident(store, incident_id)
                    messages = security_intelligence.build_ai_messages(analysis)
                    submit_body = {"messages": messages, "max_tokens": 1400, "temperature": 0.1,
                                   "priority": "normal"}
                    deployment_id = str(body.get("deployment_id", "")).strip()
                    if deployment_id:
                        submit_body["deployment_id"] = deployment_id
                    job = ai_control.submit(actor["name"], submit_body, actor_id=actor["id"])
                    self._send(202, {"ok": True, "job": job, "analysis_context": {
                        "incident_id": incident_id, "evidence_events": analysis["evidence_summary"]["events"],
                        "related_incidents": analysis["evidence_summary"]["related_incidents"]}})
                elif path.startswith("/api/v203/security/ingest/"):
                    actor = self._actor("security:ingest")
                    source = path.rsplit("/", 1)[-1]
                    items = body.get("events") if isinstance(body.get("events"), list) else [body.get("event", body)]
                    result = security_ops.ingest(store, source, items, actor["name"])
                    self._send(202, {"ok": True, "result": result})
                elif path == "/api/v203/security/incidents/update":
                    actor = self._actor("security:incident:update")
                    incident_id = str(body.get("incident_id", ""))
                    self._send(200, {"ok": True, "incident": security_ops.update_incident(store, incident_id, body, actor["name"])})
                elif path == "/api/v203/security/playbooks/plan":
                    actor = self._actor("security:playbook:plan")
                    result = security_ops.plan_playbook(store, str(body.get("incident_id", "")), str(body.get("playbook_id", "")), actor)
                    self._send(201, {"ok": True, "run": result})
                elif path.startswith("/api/v203/security/playbooks/") and path.endswith("/approve"):
                    actor = self._actor("security:playbook:approve")
                    run_id = path.split("/")[-2]
                    self._send(200, {"ok": True, "run": security_ops.approve_playbook(store, run_id, actor)})
                elif path.startswith("/api/v203/security/playbooks/") and path.endswith("/execute"):
                    actor = self._actor("security:playbook:approve")
                    run_id = path.split("/")[-2]
                    self._send(200, {"ok": True, "result": security_ops.execute_playbook(store, run_id, actor)})
                elif path == "/api/v200/nodes/report":
                    node_id = self.headers.get("X-CF-Node-ID", "")
                    node_token = self.headers.get("X-CF-Node-Token", "")
                    timestamp = int(self.headers.get("X-CF-Timestamp", "0"))
                    nonce = self.headers.get("X-CF-Nonce", "")
                    store.accept_node_report(node_id, node_token, timestamp, nonce, body)
                    self._send(200, {"ok": True, "received_at": utc_now()})
                elif path == "/api/v200/nodes/enroll":
                    actor = self._actor()
                    if actor["role"] != "admin":
                        raise PermissionError("forbidden")
                    data = store.create_node(str(body.get("name", "")), body.get("labels") if isinstance(body.get("labels"), dict) else {})
                    self._send(201, {"ok": True, **data, "agent_config": {"CF_NODE_ID": data["node_id"], "CF_NODE_TOKEN": data["token"]}})
                elif path.startswith("/api/v200/nodes/") and path.endswith("/revoke"):
                    actor = self._actor()
                    if actor["role"] != "admin":
                        raise PermissionError("forbidden")
                    node_id = path.split("/")[-2]
                    if not store.revoke_node(node_id, actor["name"]):
                        self._error(404, "not_found")
                    else:
                        self._send(200, {"ok": True})
                elif path == "/api/v200/tokens":
                    actor = self._actor()
                    if actor["role"] != "admin":
                        raise PermissionError("forbidden")
                    role = str(body.get("role", "viewer"))
                    name = str(body.get("name", ""))
                    requested_scopes = body.get("scopes")
                    if requested_scopes is not None:
                        if not isinstance(requested_scopes, list) or not all(isinstance(x, str) for x in requested_scopes):
                            raise ValueError("invalid_request")
                        allowed_scopes = set(__import__("server_core").ROLE_SCOPES.get(role, []))
                        if "*" not in allowed_scopes and not set(requested_scopes).issubset(allowed_scopes):
                            raise PermissionError("forbidden")
                    data = store.create_token(name, role, requested_scopes)
                    self._send(201, {"ok": True, **data})
                elif path.startswith("/api/v200/tokens/") and path.endswith("/revoke"):
                    actor = self._actor()
                    if actor["role"] != "admin":
                        raise PermissionError("forbidden")
                    token_id = path.split("/")[-2]
                    if not store.revoke_token(token_id, actor["name"]):
                        self._error(404, "not_found")
                    else:
                        self._send(200, {"ok": True})
                elif path == "/api/v200/workflows/plan":
                    actor = self._actor("workflows:plan")
                    wid = store.add_workflow(str(body.get("title", "")), body.get("steps", []), actor["name"])
                    self._send(201, {"ok": True, "workflow_id": wid, "status": "pending_approval", "expires_in_seconds": 600})
                elif path.startswith("/api/v200/workflows/") and path.endswith("/approve"):
                    actor = self._actor("workflows:approve")
                    wid = path.split("/")[-2]
                    store.approve_workflow(wid, actor["name"])
                    self._send(200, {"ok": True, "status": "approved"})
                elif path.startswith("/api/v200/workflows/") and path.endswith("/execute"):
                    actor = self._actor("workflows:approve")
                    wid = path.split("/")[-2]
                    result = run_workflow(store, wid, actor["name"], data_dir)
                    self._send(200, {"ok": True, "result": _json_safe(result)})
                elif path == "/api/v200/integrations/test":
                    actor = self._actor("integrations:test")
                    connector_id = str(body.get("id", ""))
                    result = connectors.test_connector(connector_id)
                    with store.lock, store.connect() as con:
                        store.audit(con, actor["name"], "integration.tested", connector_id,
                                    {"connected": result["connected"], "http_status": result["http_status"], "latency_ms": result["latency_ms"]})
                    self._send(200, {"ok": True, "result": result})
                elif path == "/api/v200/ai/chat":
                    actor = self._actor("ai:invoke")
                    result = ai.chat(actor["name"], body)
                    self._send(200, {"ok": True, **result})
                elif path == "/api/v201/ai/jobs":
                    actor = self._actor("ai:invoke")
                    result = ai_control.submit(actor["name"], body, actor_id=actor["id"])
                    self._send(202, {"ok": True, **result})
                elif path == "/api/v201/ai/models/health":
                    self._actor("ai:health")
                    self._send(200, {"results": ai_control.check_all()})
                elif path.startswith("/api/v201/ai/models/") and path.endswith("/health"):
                    self._actor("ai:health")
                    deployment_id = path.split("/")[-2]
                    self._send(200, ai_control.health_check(deployment_id))
                elif path.startswith("/api/v201/ai/models/") and path.endswith("/policy"):
                    actor = self._actor("ai:models:manage")
                    deployment_id = path.split("/")[-2]
                    self._send(200, {"ok": True, "model": ai_control.set_policy(deployment_id, body, actor["name"])})
                else:
                    self._error(404, "not_found")
            except OverflowError as exc:
                code = str(exc)
                self._error(429 if code == "ai_queue_full" else 413, code if code in ERROR_MESSAGES["en"] else "invalid_request")
            except PermissionError as exc:
                code = str(exc)
                self._error(401 if code in {"unauthorized", "node_auth_failed"} else 403,
                            code if code in ERROR_MESSAGES["en"] else "forbidden")
            except KeyError as exc:
                code = str(exc).strip("'\"")
                known = code if code in ERROR_MESSAGES["en"] else "not_found"
                self._error(404, known)
            except TimeoutError as exc:
                self._error(409, str(exc) if str(exc) in ERROR_MESSAGES["en"] else "invalid_request")
            except (ValueError, TypeError) as exc:
                code = str(exc)
                known = code if code in ERROR_MESSAGES["en"] else "invalid_request"
                self._error(400, known)
            except connectors.ConnectorError as exc:
                self._error(502, exc.code if exc.code in ERROR_MESSAGES["en"] else "internal_error")
            except RuntimeError as exc:
                code = str(exc)
                self._error(502 if code.startswith("ai_provider") else 409,
                            code if code in ERROR_MESSAGES["en"] else "internal_error")
            except Exception:
                self._error(500, "internal_error")

    return Handler


STARTED = time.monotonic()


def serve(args):
    if platform.system() != "Linux":
        raise SystemExit("CyberForge Server Edition v2.1.0 is Linux-only. Use the separate CyberForge AIO Desktop branch on Windows/macOS.")
    bind = args.bind or os.getenv("CF_SERVER_BIND", "127.0.0.1")
    port = args.port or int(os.getenv("CF_SERVER_PORT", "8787"))
    # Loopback remains the default. Private numeric binds require an explicit
    # opt-in and trusted proxy CIDR allowlist; public/unspecified binds are refused.
    allow_private = os.getenv("CF_SERVER_ALLOW_PRIVATE_BIND", "0") == "1"
    if not is_allowed_bind_address(bind, allow_private=allow_private):
        raise SystemExit("Control plane binds to loopback by default. A private IP requires CF_SERVER_ALLOW_PRIVATE_BIND=1; public/unspecified addresses are refused.")
    if bind not in {"127.0.0.1", "::1", "localhost"}:
        if os.getenv("CF_SERVER_TRUST_PROXY", "0") != "1":
            raise SystemExit("A private bind requires CF_SERVER_TRUST_PROXY=1.")
        try:
            proxy_networks = configured_proxy_networks()
        except ValueError as exc:
            raise SystemExit("CF_SERVER_TRUST_PROXY_CIDRS contains an invalid network.") from exc
        if not proxy_networks:
            raise SystemExit("A private bind requires CF_SERVER_TRUST_PROXY_CIDRS so only known reverse proxies can connect.")
    data_dir = Path(args.data_dir).expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(data_dir, 0o700)
    except OSError:
        pass
    store = create_store(data_dir)
    if not store.verify_audit()["valid"]:
        raise SystemExit("Audit chain verification failed. Refusing to start.")
    with store.connect() as con:
        active = con.execute("SELECT COUNT(*) n FROM api_tokens WHERE revoked=0").fetchone()["n"]
    if not active:
        raise SystemExit("No active API token. Run: python server.py init-admin")
    ai = AIService(store)
    ai_control = AIControlPlane(store, ai)
    handler = create_handler(store, ai, data_dir, ai_control)
    concurrency = int(os.getenv("CF_SERVER_MAX_CONCURRENCY", "64"))
    httpd = BoundedThreadingHTTPServer((bind, port), handler, max_concurrency=concurrency)
    print(f"{APP_NAME} {VERSION} listening at http://{bind}:{port}")
    print(f"Data directory: {data_dir}")
    print(f"Storage backend: {getattr(store, 'backend', 'sqlite')}")
    print(f"Max concurrent requests: {httpd.max_concurrency}")
    if bind in {"127.0.0.1", "::1", "localhost"}:
        print("Loopback-only bind. Put Caddy/Nginx in front for remote access and TLS.")
    else:
        print("Private-network bind enabled. Firewall this address to the configured trusted proxy CIDRs only.")
    try:
        httpd.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping CyberForge Server Edition...")
    finally:
        httpd.server_close()
        ai_control.close()



def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _backup_database(store, data_dir: Path, output: str | None = None) -> dict:
    data_dir = Path(data_dir).expanduser().resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    if output:
        raw_target = Path(output).expanduser()
    else:
        ext = "dump" if getattr(store, "backend", "sqlite") == "postgres" else "sqlite3"
        raw_target = data_dir / "backups" / f"cyberforge-{stamp}.{ext}"
    if raw_target.exists() or raw_target.is_symlink():
        raise FileExistsError("Backup target already exists; choose a new unique path.")
    target = raw_target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.exists() or target.is_symlink():
        raise FileExistsError("Resolved backup target already exists; choose a new unique path.")
    previous_umask = os.umask(0o077)
    if getattr(store, "backend", "sqlite") == "postgres":
        try:
            result = store.backup_database(target)
            verification = verify_backup_file(target)
            if not verification.get("valid"):
                raise RuntimeError("PostgreSQL backup verification failed")
            result["sha256"] = verification["sha256"]
            result["verified"] = True
            return result
        except Exception:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        finally:
            os.umask(previous_umask)
    try:
        source_path = Path(store.db_path)
        if not source_path.is_file():
            raise RuntimeError("SQLite database file does not exist")
        if target.resolve() == source_path.resolve():
            raise ValueError("Backup target must not be the source database")
        source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True, timeout=10)
        dest = None
        try:
            dest = sqlite3.connect(target, timeout=10)
            source.backup(dest)
            check = dest.execute("PRAGMA quick_check").fetchone()
            if not check or check[0] != "ok":
                raise RuntimeError("SQLite backup quick_check failed")
        finally:
            if dest is not None:
                dest.close()
            source.close()
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        return {"path": str(target), "size_bytes": target.stat().st_size,
                "sha256": _sha256_file(target), "format": "sqlite", "verified": True}
    except Exception:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        os.umask(previous_umask)


def verify_backup_file(path: Path) -> dict:
    path = Path(path).expanduser().resolve()
    if not path.is_file() or path.stat().st_size == 0:
        return {"valid": False, "path": str(path), "reason": "backup_missing_or_empty"}
    # SQLite files have a stable 16-byte magic header.
    with path.open("rb") as handle:
        magic = handle.read(16)
    if magic == b"SQLite format 3\x00":
        con = None
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
            result = con.execute("PRAGMA quick_check").fetchone()
            ok = bool(result and result[0] == "ok")
            return {"valid": ok, "format": "sqlite", "path": str(path),
                    "size_bytes": path.stat().st_size, "sha256": _sha256_file(path),
                    "reason": None if ok else "sqlite_quick_check_failed"}
        except sqlite3.DatabaseError:
            return {"valid": False, "format": "sqlite", "path": str(path),
                    "size_bytes": path.stat().st_size,
                    "sha256": _sha256_file(path),
                    "reason": "sqlite_quick_check_failed"}
        finally:
            if con is not None:
                con.close()
    pg_restore = shutil.which("pg_restore")
    if pg_restore and path.suffix.lower() in {".dump", ".backup", ".pgdump"}:
        cp = subprocess.run([pg_restore, "--list", str(path)], capture_output=True, text=True, timeout=30, check=False)
        return {"valid": cp.returncode == 0, "format": "pg_dump_custom", "path": str(path),
                "size_bytes": path.stat().st_size, "sha256": _sha256_file(path),
                "reason": None if cp.returncode == 0 else "pg_restore_list_failed"}
    return {"valid": False, "path": str(path), "reason": "unknown_backup_format_or_pg_restore_missing"}


def run_preflight(data_dir: Path) -> dict:
    data_dir = Path(data_dir).expanduser().resolve()
    store = create_store(data_dir)
    security_ops.initialize(store)
    threat_intel.initialize(store)
    audit = store.verify_audit()
    if not audit.get("valid"):
        raise SystemExit("Audit chain verification failed during preflight.")
    with store.connect() as con:
        active_tokens = int(con.execute("SELECT COUNT(*) n FROM api_tokens WHERE revoked=0").fetchone()["n"])
    result = {"ok": True, "version": VERSION, "storage_backend": getattr(store, "backend", "sqlite"),
              "data_dir": str(data_dir), "audit": audit, "active_tokens": active_tokens,
              "threat_intelligence": threat_intel.summary(store), "detection_engine": detection_engine.summary(store)}
    return result


def main():
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--data-dir", default=os.getenv("CF_SERVER_DATA_DIR", str(DATA_DIR)))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-admin", help="Create the first administrator token")
    tokenp = sub.add_parser("create-token", help="Create an API token")
    tokenp.add_argument("--name", required=True)
    tokenp.add_argument("--role", choices=["admin", "operator", "analyst", "viewer", "sensor"], default="viewer")
    nodep = sub.add_parser("create-node", help="Enroll a node and print one-time agent credentials")
    nodep.add_argument("--name", required=True)
    nodep.add_argument("--labels", default="{}")
    srv = sub.add_parser("serve", help="Start the Linux server control plane")
    srv.add_argument("--bind", default=None)
    srv.add_argument("--port", type=int, default=None)
    doctor = sub.add_parser("doctor", help="Read-only Linux runtime and integration check")
    verify = sub.add_parser("verify-audit", help="Verify the audit hash chain")
    sub.add_parser("generate-data-key", help="Generate a 256-bit key for encrypted distributed AI job payloads")
    sub.add_parser("token-count", help="Print the number of active API tokens")
    preflight = sub.add_parser("preflight", help="Initialize additive schemas and verify the deployment before service start")
    backup = sub.add_parser("backup", help="Create and hash a database backup")
    backup.add_argument("--output", default=None, help="Backup output path (defaults to the data-dir backups folder)")
    verify_backup = sub.add_parser("verify-backup", help="Verify a SQLite or PostgreSQL custom-format backup")
    verify_backup.add_argument("--path", required=True, help="Backup file path")
    args = parser.parse_args()
    data_dir = Path(args.data_dir).expanduser().resolve()
    if args.command == "serve":
        serve(args)
        return
    if args.command == "generate-data-key":
        print(EnvelopeCipher.generate_key())
        return
    if args.command == "verify-backup":
        # Verification is intentionally independent of the configured live DB;
        # operators can validate an offline recovery artifact without connecting
        # to PostgreSQL or creating/modifying the active data directory.
        result = verify_backup_file(Path(args.path))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(0 if result["valid"] else 2)
    data_dir.mkdir(parents=True, exist_ok=True)
    store = create_store(data_dir)
    if args.command == "preflight":
        print(json.dumps(run_preflight(data_dir), ensure_ascii=False, indent=2))
        return
    if args.command == "backup":
        try:
            result = _backup_database(store, data_dir, args.output)
        except Exception as exc:
            raise SystemExit(f"Backup failed: {type(exc).__name__}: {exc}") from None
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if args.command == "init-admin":
        with store.connect() as con:
            count = con.execute("SELECT COUNT(*) n FROM api_tokens WHERE revoked=0").fetchone()["n"]
        if count:
            raise SystemExit("An active token already exists. Use create-token if you are authenticated via the API.")
        created = store.create_token("bootstrap-admin", "admin")
        print("IMPORTANT: copy this token now. It is shown once and is not recoverable.\n")
        print(created["token"])
        print(f"\nToken ID: {created['token_id']}\nStorage backend: {getattr(store, 'backend', 'sqlite')}")
    elif args.command == "token-count":
        with store.connect() as con:
            print(int(con.execute("SELECT COUNT(*) n FROM api_tokens WHERE revoked=0").fetchone()["n"]))
    elif args.command == "create-token":
        created = store.create_token(args.name, args.role)
        print(json.dumps(created, indent=2))
    elif args.command == "create-node":
        try:
            labels = json.loads(args.labels)
        except json.JSONDecodeError:
            raise SystemExit("--labels must be JSON object")
        if not isinstance(labels, dict):
            raise SystemExit("--labels must be JSON object")
        created = store.create_node(args.name, labels)
        print("IMPORTANT: store this node token securely. It is shown once.\n")
        print(json.dumps({"CF_NODE_ID": created["node_id"], "CF_NODE_TOKEN": created["token"]}, indent=2))
    elif args.command == "doctor":
        print(json.dumps({"version": VERSION, "storage_backend": getattr(store, "backend", "sqlite"),
                          "host": host_inventory(data_dir), "integrations": integrations.catalog_summary(),
                          "ai_runtimes": __import__("server_core").runtime_inventory(), "gpu": gpu_inventory(),
                          "ai_scheduler": scheduler_config(), "audit": store.verify_audit()}, indent=2))
    elif args.command == "verify-audit":
        result = store.verify_audit()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["valid"] else 2)


if __name__ == "__main__":
    main()
