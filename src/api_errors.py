"""/api 错误响应脱敏：内部异常与校验详情回显前统一去除凭据。"""

import re


_SECRET_ERROR_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|private[-_ ]?key|access[-_ ]?key)"
    r"\s*[:=]\s*([^,;\s}]+)"
)
_SECRET_DETAIL_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "private-key",
    "private_key",
    "access-key",
    "access_key",
}


def _safe_error_text(value: object, fallback: str = "请求失败") -> str:
    """把内部异常转换为不含凭据的短错误文本。"""
    text = str(value or "").strip()
    text = _SECRET_ERROR_PATTERN.sub(r"\1=[已隐藏]", text)
    # 避免 traceback/路径/超长响应被错误地回显到 API。
    text = text.replace("\x00", "")[:1000]
    return text or fallback


def _redact_error_details(value: object):
    if isinstance(value, dict):
        return {
            key: _redact_error_details(item)
            for key, item in value.items()
            if str(key).lower() not in _SECRET_DETAIL_KEYS
        }
    if isinstance(value, list):
        return [_redact_error_details(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_error_details(item) for item in value]
    if isinstance(value, str):
        return _safe_error_text(value)
    return value


def _api_error_payload(detail: object, fallback: str = "请求失败") -> dict:
    if isinstance(detail, dict):
        error = _safe_error_text(detail.get("error") or detail.get("message"), fallback)
        extra = {
            key: _redact_error_details(value)
            for key, value in detail.items()
            if key not in {"error", "message"}
        }
        payload = {"ok": False, "error": error}
        if extra:
            payload["details"] = extra
        return payload
    return {"ok": False, "error": _safe_error_text(detail, fallback)}
