"""表单登录与 JSON 登录共用的认证辅助：Cookie、来源校验、登录锁与注册限流。

只包含纯函数与进程内状态，不构建 FastAPI app；路由仍在 api.py 中装配。
"""

import hashlib
import os
import threading
import time
from collections import OrderedDict, deque
from urllib.parse import quote

from fastapi import Request, Response
from fastapi.responses import RedirectResponse

from auth import get_bool_env
from security import csrf_session_binding, is_trusted_request_origin, request_client_ip, validate_csrf_token
from storage import (
    authenticate_user,
    create_auth_session,
    get_public_base_url,
    recent_login_failure_counts,
    record_auth_audit_event,
)


AUTH_COOKIE_NAME = "clash_config_gen_session"
AUTH_COOKIE_DAYS = 30


def _auth_redirect(message: str = "") -> RedirectResponse:
    target = "/" if not message else f"/?auth_error={quote(message)}"
    return RedirectResponse(target, status_code=303)


def _set_auth_cookie(response: Response, token: str, remember: bool) -> None:
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        max_age=AUTH_COOKIE_DAYS * 86400 if remember else None,
        httponly=True,
        secure=get_bool_env("AUTH_COOKIE_SECURE", True),
        samesite="lax",
        path="/",
    )


def _auth_client_ip(request: Request) -> str:
    peer_ip = request.client.host if request.client else ""
    return request_client_ip(peer_ip, request.headers.get("x-forwarded-for", ""))


def _request_session_binding(request: Request) -> str:
    """当前请求 Cookie 中会话 token 的摘要，用于校验会话绑定的 CSRF token。"""
    return csrf_session_binding(request.cookies.get(AUTH_COOKIE_NAME, ""))


def _is_valid_auth_request(request: Request, csrf_token: str, action: str, binding: str = "") -> bool:
    """Origin/Referer + CSRF 校验；binding 非空时 token 必须由同一会话签发。"""
    return is_trusted_request_origin(
        request.headers.get("origin", ""),
        request.headers.get("referer", ""),
        get_public_base_url(),
    ) and validate_csrf_token(csrf_token, action, binding=binding)


def _positive_int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except ValueError:
        return default


# 登录“检查阈值 → 校验密码 → 记录失败”必须对同一用户名串行，否则并发请求
# 会在失败记录落库前同时通过阈值检查。按用户名哈希分桶，锁数量固定，
# 不会因为攻击者枚举用户名而无限增长；仅覆盖本进程（FastAPI 是唯一登录入口）。
_LOGIN_LOCK_STRIPES = tuple(threading.Lock() for _ in range(256))


def _login_lock_for(normalized_username: str) -> threading.Lock:
    digest = hashlib.sha256(normalized_username.encode("utf-8")).digest()
    return _LOGIN_LOCK_STRIPES[int.from_bytes(digest[:2], "big") % len(_LOGIN_LOCK_STRIPES)]


def _try_login(username: str, password: str, persistent: bool, client_ip: str) -> dict:
    """供表单登录与 JSON 登录共用的认证逻辑；返回统一结果字典。"""
    normalized_username = username.strip().lower()
    with _login_lock_for(normalized_username):
        return _try_login_locked(username, normalized_username, password, persistent, client_ip)


def _try_login_locked(
    username: str,
    normalized_username: str,
    password: str,
    persistent: bool,
    client_ip: str,
) -> dict:
    window_seconds = _positive_int_env("AUTH_RATE_LIMIT_WINDOW_SECONDS", 900)
    account_limit = _positive_int_env("AUTH_RATE_LIMIT_ACCOUNT_FAILURES", 5)
    ip_limit = _positive_int_env("AUTH_RATE_LIMIT_IP_FAILURES", 20)
    account_failures, ip_failures = recent_login_failure_counts(
        normalized_username,
        client_ip,
        window_seconds,
    )
    if account_failures >= account_limit or ip_failures >= ip_limit:
        record_auth_audit_event("login_blocked", normalized_username, client_ip, False, "rate_limit")
        return {"ok": False, "blocked": True, "error": "登录尝试过于频繁，请稍后再试。"}

    user = authenticate_user(username, password)
    if not user:
        record_auth_audit_event("login", normalized_username, client_ip, False, "invalid_credentials")
        return {"ok": False, "blocked": False, "error": "用户名或密码错误，或账号已被禁用。"}

    token = create_auth_session(
        int(user["id"]),
        days=AUTH_COOKIE_DAYS if persistent else 1,
    )
    record_auth_audit_event("login", str(user["username"]), client_ip, True, "authenticated")
    return {"ok": True, "token": token, "persistent": persistent, "user": user}


# 注册频率限制：进程内按 IP 的滑动窗口，在 PBKDF2 与写库之前拦截。
# 记录总量设上限，避免伪造大量来源时内存无限增长。
_REGISTER_ATTEMPTS: "OrderedDict[str, deque]" = OrderedDict()
_REGISTER_ATTEMPTS_GUARD = threading.Lock()
_REGISTER_ATTEMPTS_MAX_KEYS = 10000


def _register_rate_limit_window() -> int:
    return _positive_int_env("REGISTER_RATE_LIMIT_WINDOW_SECONDS", 3600)


def _register_rate_limited(client_ip: str) -> bool:
    """记录一次注册尝试；超过阈值时返回 True（本次不计入）。"""
    limit = _positive_int_env("REGISTER_RATE_LIMIT_PER_WINDOW", 10)
    window = _register_rate_limit_window()
    now = time.monotonic()
    key = client_ip or "unknown"
    with _REGISTER_ATTEMPTS_GUARD:
        attempts = _REGISTER_ATTEMPTS.get(key)
        if attempts is None:
            attempts = deque()
            _REGISTER_ATTEMPTS[key] = attempts
        _REGISTER_ATTEMPTS.move_to_end(key)
        while attempts and now - attempts[0] >= window:
            attempts.popleft()
        if len(attempts) >= limit:
            return True
        attempts.append(now)
        while len(_REGISTER_ATTEMPTS) > _REGISTER_ATTEMPTS_MAX_KEYS:
            _REGISTER_ATTEMPTS.popitem(last=False)
        return False
