import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import time
from urllib.parse import urlsplit


CSRF_TOKEN_TTL_SECONDS = 3600


def _csrf_secret() -> bytes:
    secret = os.getenv("CSRF_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("CSRF_SECRET 必须设置为至少 32 个字符")
    return secret.encode("utf-8")


def create_csrf_token(action: str, now: int | None = None) -> str:
    issued_at = int(time.time() if now is None else now)
    payload = f"{action}:{issued_at}:{secrets.token_urlsafe(18)}"
    signature = hmac.new(_csrf_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    raw_token = f"{payload}:{signature}".encode("utf-8")
    return base64.urlsafe_b64encode(raw_token).decode("ascii").rstrip("=")


def validate_csrf_token(
    token: str,
    action: str,
    now: int | None = None,
    ttl_seconds: int = CSRF_TOKEN_TTL_SECONDS,
) -> bool:
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        token_action, issued_at_text, nonce, supplied_signature = raw.split(":", 3)
        issued_at = int(issued_at_text)
        current = int(time.time() if now is None else now)
        if token_action != action or not nonce or issued_at > current + 30:
            return False
        if current - issued_at > max(60, ttl_seconds):
            return False
        payload = f"{token_action}:{issued_at}:{nonce}"
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


def request_client_ip(peer_ip: str, forwarded_for: str = "") -> str:
    peer = _valid_ip(peer_ip)
    if peer in {"127.0.0.1", "::1"} and forwarded_for:
        # OpenResty 追加的最后一个地址最接近可信代理，避免采用可伪造的首段。
        forwarded = _valid_ip(forwarded_for.split(",")[-1].strip())
        if forwarded:
            return forwarded
    return peer or "unknown"


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
