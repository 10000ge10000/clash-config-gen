import base64
import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
import time
from urllib.parse import urlsplit


CSRF_TOKEN_TTL_SECONDS = 3600
LOGGER = logging.getLogger(__name__)
DEFAULT_TRUSTED_PROXY_CIDRS = "127.0.0.1/32,::1/128"
# 文档/示例中的占位值：出现这些片段说明运维没有替换 CSRF_SECRET。
_PLACEHOLDER_SECRET_MARKERS = ("change-me", "change-this", "replace-with")


def _csrf_secret() -> bytes:
    secret = os.getenv("CSRF_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("CSRF_SECRET 必须设置为至少 32 个字符")
    lowered = secret.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_SECRET_MARKERS):
        raise RuntimeError("CSRF_SECRET 仍是示例占位值，请改为随机密钥（例如 openssl rand -hex 32 的输出）")
    return secret.encode("utf-8")


def ensure_csrf_secret() -> None:
    """启动期校验 CSRF_SECRET；不合规直接抛 RuntimeError，让服务启动失败而不是等到首个请求。"""
    _csrf_secret()


def csrf_session_binding(session_token: str) -> str:
    """会话绑定摘要：sha256(session_token) 前 16 字节的十六进制；无会话返回空串。

    只放摘要进 token，避免会话凭据本身出现在页面或日志中。
    """
    if not session_token:
        return ""
    return hashlib.sha256(session_token.encode("utf-8")).hexdigest()[:32]


def create_csrf_token(action: str, now: int | None = None, binding: str = "") -> str:
    """签发 CSRF token；binding 非空时把会话摘要纳入 HMAC，换号后旧 token 失效。

    未绑定的 token 保持原 action:时间:随机数 载荷格式（auth/logout 等用途）。
    """
    issued_at = int(time.time() if now is None else now)
    payload = f"{action}:{issued_at}:{secrets.token_urlsafe(18)}"
    if binding:
        payload = f"{payload}:{binding}"
    signature = hmac.new(_csrf_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    raw_token = f"{payload}:{signature}".encode("utf-8")
    return base64.urlsafe_b64encode(raw_token).decode("ascii").rstrip("=")


def validate_csrf_token(
    token: str,
    action: str,
    now: int | None = None,
    ttl_seconds: int = CSRF_TOKEN_TTL_SECONDS,
    binding: str = "",
) -> bool:
    """校验签名、用途、时效与会话绑定；binding 必须与签发时完全一致（含都为空）。"""
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        parts = raw.split(":")
        if len(parts) == 4:
            token_action, issued_at_text, nonce, supplied_signature = parts
            token_binding = ""
        elif len(parts) == 5:
            token_action, issued_at_text, nonce, token_binding, supplied_signature = parts
            if not token_binding:
                return False
        else:
            return False
        issued_at = int(issued_at_text)
        current = int(time.time() if now is None else now)
        if token_action != action or not nonce or issued_at > current + 30:
            return False
        if current - issued_at > max(60, ttl_seconds):
            return False
        if not hmac.compare_digest(token_binding, binding or ""):
            return False
        payload = f"{token_action}:{issued_at}:{nonce}"
        if token_binding:
            payload = f"{payload}:{token_binding}"
        expected = hmac.new(_csrf_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(supplied_signature, expected)
    except Exception:
        return False


def is_trusted_request_origin(origin: str, referer: str, public_base_url: str) -> bool:
    allowed_origins = {_origin(public_base_url)}
    allowed_origins.update(
        _origin(value.strip())
        for value in os.getenv("AUTH_ALLOWED_ORIGINS", "").split(",")
        if value.strip()
    )
    allowed_origins.discard("")
    supplied_origin = _origin(origin) if origin else _origin(referer)
    return bool(supplied_origin and supplied_origin in allowed_origins)


def _trusted_proxy_networks() -> list:
    """解析 TRUSTED_PROXY_CIDRS；非法条目记录 warning 后忽略。"""
    raw = os.getenv("TRUSTED_PROXY_CIDRS", DEFAULT_TRUSTED_PROXY_CIDRS)
    networks = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            LOGGER.warning("TRUSTED_PROXY_CIDRS 含非法 CIDR，已忽略: %s", item)
    return networks


def _is_trusted_proxy(peer: str, networks: list | None = None) -> bool:
    if not peer:
        return False
    address = ipaddress.ip_address(peer)
    if networks is None:
        networks = _trusted_proxy_networks()
    return any(address.version == net.version and address in net for net in networks)


def request_client_ip(peer_ip: str, forwarded_for: str = "") -> str:
    peer = _valid_ip(peer_ip)
    networks = _trusted_proxy_networks()
    if not forwarded_for or not _is_trusted_proxy(peer, networks):
        return peer or "unknown"
    # 从右往左跳过可信代理（如 docker 网关、Cloudflare 边缘），第一个不可信地址即真实客户端；
    # 更左侧的条目可能由客户端伪造，不予采用。
    client = ""
    for item in reversed(forwarded_for.split(",")):
        candidate = _valid_ip(item.strip())
        if not candidate:
            break
        client = candidate
        if not _is_trusted_proxy(candidate, networks):
            break
    return client or peer or "unknown"


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""
