import copy
import difflib
import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from urllib.parse import quote

if os.name == "nt":
    import msvcrt
else:
    import fcntl

import yaml
from fastapi import FastAPI, Form, HTTPException, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from auth import get_bool_env
from config_builder import DEFAULT_RULE_TYPE, DUSTINWIN_PROVIDERS_MAP, LHIE1_PROVIDERS_MAP, is_no_base_rule_type
from config_builder import (
    build_config,
    build_subscription_headers,
    build_yaml,
    validate_config,
)
from config_defaults import (
    FULL_CLIENT_DNS_PRESET,
    GLOBAL_CONFIG_SCHEMA,
    OPENCLASH_ROUTER_SAFE_PRESET,
    apply_v2_global_defaults,
    build_default_global_config,
)
from diagnostics import build_subscription_diagnostics
from importers import (
    fetch_text_from_external_url,
    normalize_subscription_content,
    parse_proxy_yaml,
    parse_share_link,
    safe_ruleset_file_path,
    tag_import_source,
    validate_ruleset_alias,
)
from mihomo_validator import validate_with_mihomo
from node_builder import NODE_FORM_SCHEMA, build_manual_node
from normalizer import normalize_proxies, normalize_proxies_for_mihomo
from ruleset_updater import get_ruleset_cache_path, start_ruleset_update_worker
from security import (
    create_csrf_token,
    is_trusted_request_origin,
    request_client_ip,
    validate_csrf_token,
)
from storage import (
    authenticate_user,
    create_auth_session,
    create_user,
    delete_regular_user,
    ensure_admin_from_env,
    get_config_by_token,
    get_public_base_url,
    get_user_by_auth_session,
    get_user_by_id,
    get_user_config,
    health_snapshot,
    init_db,
    list_users,
    recent_login_failure_counts,
    record_auth_audit_event,
    reset_subscription_token,
    revoke_auth_session,
    save_user_config_atomic,
    save_user_draft,
    set_user_enabled,
    validate_new_user_credentials,
)
from ui.time_display import format_beijing_time


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    ensure_admin_from_env()
    _retry_ruleset_tombstones()
    start_ruleset_update_worker()
    yield


app = FastAPI(title="Clash-Config-Gen Subscription API", lifespan=lifespan)
AUTH_COOKIE_NAME = "clash_config_gen_session"
AUTH_COOKIE_DAYS = 30
AUTH_ASSET_PATH = Path(__file__).with_name("assets") / "auth-future-city.png"
V2_PREVIEW_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "design" / "v2-preview.html",
    Path(__file__).with_name("design") / "v2-preview.html",
]

# /api 变更类请求统一使用这个 CSRF action，前端从 /api/session 领取。
API_CSRF_ACTION = "api"


def _is_api_request(request: Request) -> bool:
    return request.url.path == "/api" or request.url.path.startswith("/api/")


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


@app.exception_handler(StarletteHTTPException)
async def api_http_exception_handler(request: Request, exc: HTTPException):
    if _is_api_request(request):
        response = JSONResponse(
            status_code=exc.status_code,
            content=_api_error_payload(exc.detail),
        )
        if exc.headers:
            response.headers.update(exc.headers)
        return response
    # Keep legacy subscription/ruleset/health error bodies unchanged.
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def api_request_validation_exception_handler(request: Request, exc: RequestValidationError):
    if _is_api_request(request):
        validation = [
            {
                "loc": [str(item) for item in error.get("loc", ())],
                "msg": _safe_error_text(error.get("msg"), "参数无效"),
                "type": str(error.get("type") or "value_error"),
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error": "请求参数校验失败",
                "details": {"validation": validation},
            },
        )
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


@app.exception_handler(Exception)
async def api_unhandled_exception_handler(request: Request, _exc: Exception):
    if _is_api_request(request):
        return JSONResponse(status_code=500, content={"ok": False, "error": "服务器内部错误"})
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


@app.get("/v2")
def v2_preview_page():
    for candidate in V2_PREVIEW_CANDIDATES:
        if candidate.is_file():
            return FileResponse(candidate, media_type="text/html; charset=utf-8")
    raise HTTPException(status_code=404, detail="V2 预览页不存在")


@app.get("/")
def root_v2_page():
    """FastAPI 根路径与 V2 页面保持同一生产入口，便于反代和健康探测。"""
    return v2_preview_page()


@app.get("/health")
def health_check():
    return health_snapshot()


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


def _is_valid_auth_request(request: Request, csrf_token: str, action: str) -> bool:
    return is_trusted_request_origin(
        request.headers.get("origin", ""),
        request.headers.get("referer", ""),
        get_public_base_url(),
    ) and validate_csrf_token(csrf_token, action)


def _positive_int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except ValueError:
        return default


@app.get("/sub/assets/auth-future-city.png")
def auth_future_city_asset():
    if not AUTH_ASSET_PATH.is_file():
        raise HTTPException(status_code=404, detail="登录页背景资源不存在")
    return FileResponse(
        AUTH_ASSET_PATH,
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.post("/sub/auth/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    remember: str = Form(""),
    csrf_token: str = Form(...),
):
    client_ip = _auth_client_ip(request)
    normalized_username = username.strip().lower()
    if not _is_valid_auth_request(request, csrf_token, "auth"):
        record_auth_audit_event("login_rejected", normalized_username, client_ip, False, "csrf_or_origin")
        return _auth_redirect("请求验证失败，请刷新页面后重试。")

    result = _try_login(username, password, remember == "on", client_ip)
    if result["ok"]:
        response = _auth_redirect()
        _set_auth_cookie(response, result["token"], result["persistent"])
        return response
    if result["blocked"]:
        response = _auth_redirect(result["error"])
        response.headers["Retry-After"] = str(_positive_int_env("AUTH_RATE_LIMIT_WINDOW_SECONDS", 900))
        return response
    return _auth_redirect(result["error"])


def _try_login(username: str, password: str, persistent: bool, client_ip: str) -> dict:
    """供表单登录与 JSON 登录共用的认证逻辑；返回统一结果字典。"""
    normalized_username = username.strip().lower()
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


@app.post("/sub/auth/register")
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    csrf_token: str = Form(...),
):
    client_ip = _auth_client_ip(request)
    normalized_username = username.strip().lower()
    if not _is_valid_auth_request(request, csrf_token, "auth"):
        record_auth_audit_event("register_rejected", normalized_username, client_ip, False, "csrf_or_origin")
        return _auth_redirect("请求验证失败，请刷新页面后重试。")
    if not get_bool_env("ALLOW_REGISTRATION", False):
        record_auth_audit_event("register", normalized_username, client_ip, False, "registration_disabled")
        return _auth_redirect("当前部署已关闭公开注册，请联系管理员创建账号。")
    if password != password_confirm:
        record_auth_audit_event("register", normalized_username, client_ip, False, "password_mismatch")
        return _auth_redirect("两次输入的密码不一致。")
    user = None
    try:
        normalized_username = validate_new_user_credentials(username, password)
        user = create_user(normalized_username, password)
        token = create_auth_session(int(user["id"]), days=AUTH_COOKIE_DAYS)
    except ValueError as exc:
        if user is not None:
            delete_regular_user(int(user["id"]))
        record_auth_audit_event("register", normalized_username, client_ip, False, type(exc).__name__)
        return _auth_redirect(f"注册失败：{exc}")
    except Exception as exc:
        if user is not None:
            delete_regular_user(int(user["id"]))
        record_auth_audit_event("register", normalized_username, client_ip, False, type(exc).__name__)
        return _auth_redirect("注册失败：服务暂时不可用，请稍后重试。")

    response = _auth_redirect()
    _set_auth_cookie(response, token, remember=True)
    record_auth_audit_event("register", str(user["username"]), client_ip, True, "created")
    return response


@app.post("/sub/auth/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    client_ip = _auth_client_ip(request)
    if not _is_valid_auth_request(request, csrf_token, "logout"):
        record_auth_audit_event("logout_rejected", "", client_ip, False, "csrf_or_origin")
        return _auth_redirect("请求验证失败，请刷新页面后重试。")
    session_token = request.cookies.get(AUTH_COOKIE_NAME, "")
    user = get_user_by_auth_session(session_token)
    revoke_auth_session(session_token)
    record_auth_audit_event(
        "logout",
        str(user["username"]) if user else "",
        client_ip,
        bool(user),
        "revoked" if user else "session_missing",
    )
    response = _auth_redirect()
    response.delete_cookie(
        AUTH_COOKIE_NAME,
        path="/",
        secure=get_bool_env("AUTH_COOKIE_SECURE", True),
        httponly=True,
        samesite="lax",
    )
    return response


@app.get("/ruleset/dustinwin/{name}")
def get_dustinwin_ruleset(name: str):
    expected_files = {str(config["file"]) for config in DUSTINWIN_PROVIDERS_MAP.values()}
    if name not in expected_files:
        raise HTTPException(status_code=404, detail="规则集不存在")

    ruleset_path = get_ruleset_cache_path(name)
    if not ruleset_path.is_file():
        raise HTTPException(status_code=503, detail="规则集缓存尚未就绪，请稍后重试")

    media_type = "application/octet-stream" if name.endswith(".mrs") else "text/plain; charset=utf-8"
    return Response(
        content=ruleset_path.read_bytes(),
        media_type=media_type,
        headers={
            "Cache-Control": "public, max-age=3600",
            "Content-Disposition": f'inline; filename="{name}"',
            "X-Clash-Ruleset-Source": "DustinWin/ruleset_geodata",
        },
    )


@app.get("/ruleset/user/{token}/{user_id}/{filename}")
def get_user_ruleset(token: str, user_id: int, filename: str):
    """Serve one private immutable ruleset version through the active token."""
    config = get_config_by_token(token)
    if not config or int(config.get("user_id") or 0) != int(user_id):
        raise HTTPException(status_code=404, detail="规则集不存在")
    parsed = _parse_versioned_ruleset_filename(filename)
    if not parsed:
        raise HTTPException(status_code=404, detail="规则集不存在")
    try:
        user_dir = _ruleset_user_dir(user_id)
        target = _safe_user_ruleset_target(user_dir, filename)
        if target is None or not target.is_file():
            raise HTTPException(status_code=404, detail="规则集不存在")
        content = target.read_bytes()
    except HTTPException:
        raise
    except OSError as exc:
        raise HTTPException(status_code=404, detail="规则集不存在") from exc
    extension = parsed[1]
    if extension == "mrs":
        media_type = "application/octet-stream"
    elif extension == "yaml":
        media_type = "application/yaml; charset=utf-8"
    else:
        media_type = "text/plain; charset=utf-8"
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Cache-Control": "private, max-age=300",
            "Content-Disposition": f'inline; filename="{filename}"',
            "X-Clash-Ruleset-Source": "user-upload",
        },
    )


def _materialize_private_provider_urls(user_id: int, token: str, providers: object) -> bool:
    """Rewrite only current-user private provider URLs to the active token."""
    if not isinstance(providers, dict):
        return False
    changed = False
    for provider in providers.values():
        if not isinstance(provider, dict):
            continue
        filename = _private_ruleset_filename(user_id, str(provider.get("path") or ""))
        if not filename:
            continue
        next_url = _user_ruleset_url(token, user_id, filename)
        if provider.get("url") != next_url:
            provider["url"] = next_url
            changed = True
        # Private providers are fetched by the subscription client itself;
        # never let a stale/edited draft route them through a dummy proxy.
        if provider.get("proxy") != "DIRECT":
            provider["proxy"] = "DIRECT"
            changed = True
    return changed


def _materialize_private_urls_in_draft(user: dict, draft: dict, token: str | None = None) -> bool:
    active_token = token
    if active_token is None:
        active_token = str(_load_saved_config(user).get("token") or "")
    return _materialize_private_provider_urls(
        int(user["id"]),
        str(active_token or ""),
        draft.get("custom_rule_providers") if isinstance(draft, dict) else {},
    )


def _materialize_private_urls_in_loaded_config(config: dict, loaded_config: dict) -> bool:
    return _materialize_private_provider_urls(
        int(config.get("user_id") or 0),
        str(config.get("token") or ""),
        loaded_config.get("rule-providers") if isinstance(loaded_config, dict) else {},
    )


def _build_subscription_response(token: str, include_body: bool = True) -> Response:
    config = get_config_by_token(token)
    if not config:
        raise HTTPException(status_code=404, detail="订阅不存在、用户已禁用或 Token 已失效")

    final_yaml = config.get("final_yaml") or ""
    if not final_yaml.strip():
        raise HTTPException(status_code=409, detail="该用户尚未保存可用配置")

    try:
        loaded_config = yaml.safe_load(final_yaml)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"订阅 YAML 已损坏: {exc}") from exc
    if not isinstance(loaded_config, dict):
        raise HTTPException(status_code=500, detail="订阅 YAML 顶层结构不是字典")

    materialized_urls = _materialize_private_urls_in_loaded_config(config, loaded_config)

    proxies = loaded_config.get("proxies") or []
    if isinstance(proxies, list):
        loaded_config["proxies"] = normalize_proxies_for_mihomo(
            [proxy for proxy in proxies if isinstance(proxy, dict)]
        )
        final_yaml = build_yaml(loaded_config)
    elif materialized_urls:
        final_yaml = build_yaml(loaded_config)

    errors, _warnings = validate_config(
        loaded_config,
        allow_no_match=is_no_base_rule_type(config.get("selected_rule_type")),
    )
    if errors:
        raise HTTPException(status_code=409, detail=f"该用户保存的配置未通过可用性检查: {'; '.join(errors)}")

    proxy_count = len(loaded_config.get("proxies") or [])
    group_count = len(loaded_config.get("proxy-groups") or [])

    return Response(
        content=final_yaml if include_body else "",
        media_type="application/x-yaml; charset=utf-8",
        headers=build_subscription_headers(proxy_count, group_count),
    )


def _subscription_snapshot(token: str) -> tuple[dict, dict, str]:
    config = get_config_by_token(token)
    if not config:
        raise HTTPException(status_code=404, detail="订阅不存在、用户已禁用或 Token 已失效")
    final_yaml = config.get("final_yaml") or ""
    if not final_yaml.strip():
        raise HTTPException(status_code=409, detail="该用户尚未保存可用配置")
    try:
        loaded_config = yaml.safe_load(final_yaml)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"订阅 YAML 已损坏: {exc}") from exc
    if not isinstance(loaded_config, dict):
        raise HTTPException(status_code=500, detail="订阅 YAML 顶层结构不是字典")
    if _materialize_private_urls_in_loaded_config(config, loaded_config):
        final_yaml = build_yaml(loaded_config)
    return config, loaded_config, final_yaml


@app.get("/sub/{token}")
def get_subscription(token: str):
    return _build_subscription_response(token)


@app.head("/sub/{token}")
def head_subscription(token: str):
    return _build_subscription_response(token, include_body=False)


@app.get("/sub/{token}/config.yaml")
def get_subscription_yaml(token: str):
    return _build_subscription_response(token)


@app.head("/sub/{token}/config.yaml")
def head_subscription_yaml(token: str):
    return _build_subscription_response(token, include_body=False)


@app.get("/sub/{token}/diagnostics")
def get_subscription_diagnostics(token: str):
    config, loaded_config, _final_yaml = _subscription_snapshot(token)
    return build_subscription_diagnostics(config, loaded_config)


# ==========================================
# /api JSON 端点（V2 前端真实功能）
# ==========================================

MAX_DRAFT_PROXIES = 500
MAX_DRAFT_BODY_BYTES = 2 * 1024 * 1024
MAX_RULESET_UPLOAD_BYTES = 4 * 1024 * 1024
MAX_RULESET_USER_BYTES = 32 * 1024 * 1024
MAX_RULESET_USER_FILES = 100
BUILTIN_TARGETS = (
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "Proxy",
    "Domestic",
    "Others",
)
RULESET_EXTENSIONS = {"list", "yaml", "yml", "txt", "text", "mrs"}
RULESET_FORMATS = {"text", "yaml", "mrs"}
RULESET_BEHAVIORS = {"classical", "domain", "ipcidr"}
RULESET_ORDERS = {"优先 (覆盖)", "默认 (追加)", "追加", "prepend", "append"}
RULESET_FORMAT_EXTENSIONS = {"text": "txt", "yaml": "yaml", "mrs": "mrs"}

# 规则集上传需要在“配额检查 → 临时文件写入 → os.replace”整个窗口内
# 对同一用户串行化。threading.Lock 只解决同进程并发，文件锁同时覆盖
# FastAPI 与 Streamlit 两个进程；锁文件只存放在 RULESET_DIR/.locks/ 下。
_RULESET_USER_LOCKS: dict[int, threading.Lock] = {}
_RULESET_USER_LOCKS_GUARD = threading.Lock()


def _ruleset_lock_dir() -> Path:
    """Return the private, application-owned directory for process locks."""
    base_dir = Path(_ruleset_dir()).resolve()
    lexical_lock_dir = base_dir / ".locks"
    if lexical_lock_dir.is_symlink():
        raise ValueError("规则集锁目录不能是符号链接")
    lock_dir = lexical_lock_dir.resolve()
    if base_dir not in lock_dir.parents:
        raise ValueError("规则集锁目录路径越界")
    lock_dir.mkdir(parents=True, exist_ok=True)
    if lock_dir.is_symlink() or not lock_dir.is_dir():
        raise ValueError("规则集锁目录不是安全目录")
    return lock_dir


def _acquire_ruleset_file_lock(handle) -> None:
    """Acquire one byte in a lock file using only the standard library."""
    handle.seek(0)
    if handle.tell() == 0 and handle.seek(0, os.SEEK_END) == 0:
        handle.write(b"0")
        handle.flush()
        handle.seek(0)
    else:
        handle.seek(0)

    if os.name == "nt":
        # msvcrt locking is per-process and needs a real byte in the file.
        # Non-blocking attempts avoid msvcrt's implementation-dependent retry
        # interval while still making the context manager block reliably.
        while True:
            try:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                time.sleep(0.05)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _release_ruleset_file_lock(handle) -> None:
    try:
        handle.seek(0)
        if os.name == "nt":
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        # Closing the descriptor below still releases an advisory lock.  Do
        # not mask the original exception from the protected operation.
        pass


@contextmanager
def _ruleset_user_lock(user_id: int):
    """Serialize one user's ruleset lifecycle across threads and processes."""
    numeric_id = int(user_id)
    if numeric_id < 1:
        raise ValueError("用户 ID 无效")
    with _RULESET_USER_LOCKS_GUARD:
        thread_lock = _RULESET_USER_LOCKS.setdefault(numeric_id, threading.Lock())
    with thread_lock:
        lock_dir = _ruleset_lock_dir()
        lock_path = lock_dir / f"{numeric_id}.lock"
        if lock_path.is_symlink():
            raise ValueError("规则集用户锁不能是符号链接")
        try:
            if lock_path.resolve().parent != lock_dir:
                raise ValueError("规则集用户锁路径越界")
        except OSError as exc:
            raise ValueError("规则集用户锁路径无效") from exc
        handle = lock_path.open("a+b")
        try:
            _acquire_ruleset_file_lock(handle)
            yield
        finally:
            _release_ruleset_file_lock(handle)
            handle.close()


def _require_api_user(request: Request) -> dict:
    """从会话 Cookie 解析当前用户；未登录返回 401。"""
    session_token = request.cookies.get(AUTH_COOKIE_NAME, "")
    user = get_user_by_auth_session(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="未登录或会话已失效")
    return dict(user)


def _reload_ruleset_user(user_id: int) -> dict:
    """Reload a user after acquiring the ruleset lifecycle guard."""
    current = get_user_by_id(int(user_id))
    if current is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not bool(current["is_enabled"]):
        raise HTTPException(status_code=409, detail="用户已被禁用")
    return dict(current)


def _reload_admin_actor_locked(actor_id: int) -> dict:
    """Re-read the administrator inside a target-user lifecycle guard."""
    actor = get_user_by_id(int(actor_id))
    if actor is None or not bool(actor["is_enabled"]):
        raise HTTPException(status_code=401, detail="管理员会话已失效")
    if not bool(actor["is_admin"]):
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return dict(actor)


def _require_api_csrf(request: Request) -> None:
    """/api 变更请求统一校验 Origin + CSRF Token；失败返回 403。"""
    token = request.headers.get("x-csrf-token", "")
    if not _is_valid_auth_request(request, token, API_CSRF_ACTION):
        raise HTTPException(status_code=403, detail="请求验证失败，请刷新页面后重试")


def _api_user_safe_dict(user: dict) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "is_admin": bool(user["is_admin"]),
    }


@app.get("/api/session")
def api_session(request: Request):
    session_token = request.cookies.get(AUTH_COOKIE_NAME, "")
    user = get_user_by_auth_session(session_token)
    return {
        "ok": True,
        "authenticated": bool(user),
        "user": _api_user_safe_dict(dict(user)) if user else None,
        "csrf_token": create_csrf_token(API_CSRF_ACTION if user else "auth"),
        "allow_registration": get_bool_env("ALLOW_REGISTRATION", False),
    }


@app.post("/api/auth/login")
async def api_login(request: Request):
    body = await _read_json_body(request)
    client_ip = _auth_client_ip(request)
    username = body.get("username")
    password = body.get("password")
    csrf_token = body.get("csrf_token")
    if not isinstance(csrf_token, str):
        raise HTTPException(status_code=403, detail="请求验证失败，请刷新页面后重试")
    if not all(isinstance(value, str) for value in (username, password)):
        raise HTTPException(status_code=400, detail="username、password、csrf_token 必须是字符串")
    if not _is_valid_auth_request(request, csrf_token, "auth"):
        record_auth_audit_event("login_rejected", "", client_ip, False, "csrf_or_origin")
        raise HTTPException(status_code=403, detail="请求验证失败，请刷新页面后重试")

    result = _try_login(
        username,
        password,
        bool(body.get("remember")),
        client_ip,
    )
    if not result["ok"]:
        status = 429 if result["blocked"] else 401
        headers = (
            {"Retry-After": str(_positive_int_env("AUTH_RATE_LIMIT_WINDOW_SECONDS", 900))}
            if result["blocked"]
            else None
        )
        raise HTTPException(status_code=status, detail=result["error"], headers=headers)

    response = JSONResponse(
        content={
            "ok": True,
            "user": _api_user_safe_dict(dict(result["user"])),
            "csrf_token": create_csrf_token(API_CSRF_ACTION),
        },
        status_code=200,
    )
    _set_auth_cookie(response, result["token"], result["persistent"])
    return response


@app.post("/api/auth/register")
async def api_register(request: Request):
    body = await _read_json_body(request)
    client_ip = _auth_client_ip(request)
    username = body.get("username")
    password = body.get("password")
    password_confirm = body.get("password_confirm")
    csrf_token = body.get("csrf_token")
    if not isinstance(csrf_token, str):
        raise HTTPException(status_code=403, detail="请求验证失败，请刷新页面后重试")
    if not all(isinstance(value, str) for value in (username, password, password_confirm)):
        raise HTTPException(status_code=400, detail="username、password、password_confirm、csrf_token 必须是字符串")
    if not _is_valid_auth_request(request, csrf_token, "auth"):
        record_auth_audit_event("register_rejected", "", client_ip, False, "csrf_or_origin")
        raise HTTPException(status_code=403, detail="请求验证失败，请刷新页面后重试")
    if not get_bool_env("ALLOW_REGISTRATION", False):
        record_auth_audit_event("register", "", client_ip, False, "registration_disabled")
        raise HTTPException(status_code=403, detail="当前部署已关闭公开注册")

    if password != password_confirm:
        record_auth_audit_event("register", username.strip().lower(), client_ip, False, "password_mismatch")
        raise HTTPException(status_code=400, detail="两次输入的密码不一致")

    user = None
    try:
        normalized_username = validate_new_user_credentials(username, password)
        user = create_user(normalized_username, password)
        token = create_auth_session(int(user["id"]), days=AUTH_COOKIE_DAYS)
    except ValueError as exc:
        if user is not None:
            delete_regular_user(int(user["id"]))
        record_auth_audit_event("register", username.strip().lower(), client_ip, False, type(exc).__name__)
        raise HTTPException(status_code=400, detail=f"注册失败：{exc}") from exc
    except Exception as exc:
        if user is not None:
            delete_regular_user(int(user["id"]))
        record_auth_audit_event("register", username.strip().lower(), client_ip, False, type(exc).__name__)
        raise HTTPException(status_code=500, detail="注册失败：服务暂时不可用，请稍后重试") from exc

    response = JSONResponse(
        content={
            "ok": True,
            "user": _api_user_safe_dict(dict(user)),
            "csrf_token": create_csrf_token(API_CSRF_ACTION),
        },
        status_code=200,
    )
    _set_auth_cookie(response, token, remember=True)
    record_auth_audit_event("register", str(user["username"]), client_ip, True, "created")
    return response


@app.post("/api/auth/logout")
def api_logout(request: Request):
    _require_api_user(request)
    _require_api_csrf(request)
    client_ip = _auth_client_ip(request)
    session_token = request.cookies.get(AUTH_COOKIE_NAME, "")
    user = get_user_by_auth_session(session_token)
    revoke_auth_session(session_token)
    record_auth_audit_event(
        "logout",
        str(user["username"]) if user else "",
        client_ip,
        bool(user),
        "revoked" if user else "session_missing",
    )
    response = JSONResponse(content={"ok": True}, status_code=200)
    response.delete_cookie(
        AUTH_COOKIE_NAME,
        path="/",
        secure=get_bool_env("AUTH_COOKIE_SECURE", True),
        httponly=True,
        samesite="lax",
    )
    return response


async def _read_json_body(request: Request, required: bool = True) -> dict | None:
    """读取 JSON 请求体，区分空请求与格式错误，并统一限制请求大小。"""
    try:
        raw = await request.body()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="无法读取请求体") from exc
    if len(raw) > MAX_DRAFT_BODY_BYTES:
        raise HTTPException(status_code=413, detail="请求体超过 2MB，请精简节点后重试")
    if not raw.strip():
        if required:
            raise HTTPException(status_code=400, detail="请求体不能为空，必须提交 JSON")
        return None
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="请求体不是有效 JSON") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON 顶层必须是对象")
    return body


def _merged_global_config(raw_global_config: dict | None, saved_global_config: dict | None = None) -> dict:
    """合并当前草稿的全局设置；完整请求优先，旧账号缺失字段使用默认值。"""
    base = {}
    if raw_global_config is None and isinstance(saved_global_config, dict):
        base.update(saved_global_config)
    elif isinstance(raw_global_config, dict):
        base.update(raw_global_config)
    return apply_v2_global_defaults(build_default_global_config(), base)


def _draft_source(body: dict, saved_config: dict | None) -> dict:
    if isinstance(body.get("config"), dict):
        source = copy.deepcopy(body["config"])
    else:
        source = copy.deepcopy(body)
    return source


def _normalize_draft(body: dict, saved_config: dict | None = None) -> tuple[dict, dict]:
    """将旧/新请求收敛到同一份完整 canonical draft，不写入数据库。"""
    source = _draft_source(body, saved_config)
    saved = saved_config or {}
    if not isinstance(source.get("proxies"), list):
        raise HTTPException(status_code=400, detail="proxies 必须是节点数组")
    if len(source["proxies"]) > MAX_DRAFT_PROXIES:
        raise HTTPException(status_code=413, detail=f"节点数量超过上限 {MAX_DRAFT_PROXIES}")

    raw_proxies: list[dict] = []
    for index, proxy in enumerate(source["proxies"], start=1):
        if not isinstance(proxy, dict):
            raise HTTPException(status_code=400, detail=f"第 {index} 个节点必须是对象")
        raw_proxy = copy.deepcopy(proxy)
        proxy_name = str(raw_proxy.get("name") or "").strip()
        if not proxy_name:
            raise HTTPException(status_code=400, detail=f"第 {index} 个节点 name 不能为空")
        if len(proxy_name) > 128:
            raise HTTPException(status_code=400, detail=f"第 {index} 个节点 name 长度不能超过 128 字符")
        raw_proxies.append(raw_proxy)

    normalized_proxies, proxy_warnings, proxy_errors = normalize_proxies(raw_proxies)
    port_errors = [error for error in proxy_errors if "端口" in str(error)]
    if port_errors:
        # Invalid ports are input errors, not a draft validation state.  Do
        # this before any storage write so PUT/validate/publish cannot retain
        # or publish a malformed replacement node.
        raise HTTPException(status_code=400, detail="；".join(port_errors))

    raw_global = source.get("global_config")
    if raw_global is not None and not isinstance(raw_global, dict):
        raise HTTPException(status_code=400, detail="global_config 必须是对象")
    global_config = _merged_global_config(raw_global, saved.get("global_config"))

    custom_rules = source.get("custom_rules", [])
    if custom_rules is None:
        custom_rules = []
    if not isinstance(custom_rules, list):
        raise HTTPException(status_code=400, detail="custom_rules 必须是数组")
    if len(custom_rules) > 500:
        raise HTTPException(status_code=413, detail="自定义规则数量超过上限 500")
    for rule_index, rule in enumerate(custom_rules, start=1):
        if not isinstance(rule, str):
            raise HTTPException(status_code=400, detail="custom_rules 的每项必须是字符串")
        if len(rule) > 512:
            raise HTTPException(status_code=400, detail=f"第 {rule_index} 条规则长度不能超过 512 字符")
    custom_rules = copy.deepcopy(custom_rules)

    custom_rule_providers = source.get("custom_rule_providers", {})
    if custom_rule_providers is None:
        custom_rule_providers = {}
    if not isinstance(custom_rule_providers, dict):
        raise HTTPException(status_code=400, detail="custom_rule_providers 必须是对象")
    for alias, provider in custom_rule_providers.items():
        if not isinstance(provider, dict):
            raise HTTPException(status_code=400, detail="custom_rule_providers 的每项必须是对象")
        for url_key in ("url", "path"):
            url_value = provider.get(url_key)
            if url_value is not None and not isinstance(url_value, str):
                raise HTTPException(status_code=400, detail=f"规则集 {alias} 的 {url_key} 必须是字符串")
        interval_value = provider.get("interval")
        if interval_value is not None:
            if isinstance(interval_value, bool) or not isinstance(interval_value, int) or not 1 <= interval_value <= 31536000:
                raise HTTPException(status_code=400, detail=f"规则集 {alias} 的 interval 必须是 1-31536000 的整数")
    custom_rule_providers = copy.deepcopy(custom_rule_providers)

    selected_rule_type = source.get("selected_rule_type", DEFAULT_RULE_TYPE)
    if selected_rule_type is None:
        selected_rule_type = DEFAULT_RULE_TYPE
    if not isinstance(selected_rule_type, str):
        raise HTTPException(status_code=400, detail="selected_rule_type 必须是字符串")
    selected_rule_type = selected_rule_type.strip() or DEFAULT_RULE_TYPE

    import_sources = source.get("import_sources", [])
    if import_sources is None:
        import_sources = []
    if not isinstance(import_sources, list):
        raise HTTPException(status_code=400, detail="import_sources 必须是数组")
    import_sources = copy.deepcopy(import_sources)
    if any(not isinstance(item, dict) for item in import_sources):
        raise HTTPException(status_code=400, detail="import_sources 的每项必须是对象")

    source_counts: dict[str, int] = {}
    for proxy in normalized_proxies:
        source_id = str(proxy.get("_source_id") or "")
        if source_id:
            source_counts[source_id] = source_counts.get(source_id, 0) + 1
    for item in import_sources:
        item["node_count"] = source_counts.get(str(item.get("id") or ""), 0)

    canonical = {
        "proxies": normalized_proxies,
        "global_config": global_config,
        "custom_rules": custom_rules,
        "custom_rule_providers": custom_rule_providers,
        "selected_rule_type": selected_rule_type,
        "import_sources": import_sources,
    }
    return canonical, {
        "warnings": [
            f"节点规范化：{warning}"
            for warning in proxy_warnings
        ],
        "errors": [
            f"节点规范化：{error}"
            for error in proxy_errors
        ],
    }


def _draft_meta_warnings(meta: dict | None) -> list[str]:
    """把规范化阶段的错误也作为 bootstrap 警告展示，避免 GET 配置静默吞掉。"""
    meta = meta or {}
    warnings = [str(item) for item in (meta.get("warnings") or [])]
    warnings.extend(f"草稿校验：{item}" for item in (meta.get("errors") or []))
    return warnings


def _load_saved_config(user: dict) -> dict:
    return get_user_config(int(user["id"]))


def _provider_defaults() -> dict:
    # 两套规则源分别暴露，不能因为切换一套而覆盖另一套。
    return {
        "dustinwin": {
            name: str(config["target"])
            for name, config in DUSTINWIN_PROVIDERS_MAP.items()
        },
        "lhie1": {
            name: target for name, (_, target) in LHIE1_PROVIDERS_MAP.items()
        },
    }


def _safe_targets_for_draft(draft: dict) -> tuple[list[str], list[str]]:
    names = {
        str(proxy.get("name"))
        for proxy in draft.get("proxies", [])
        if isinstance(proxy, dict) and str(proxy.get("name") or "").strip()
    }
    fallback = set(BUILTIN_TARGETS) | names
    try:
        built = build_config(
            draft.get("proxies") or [],
            draft.get("global_config") or {},
            draft.get("custom_rules") or [],
            draft.get("custom_rule_providers") or {},
            draft.get("selected_rule_type") or DEFAULT_RULE_TYPE,
        )
        group_names = {
            str(group.get("name"))
            for group in built.get("proxy-groups", [])
            if isinstance(group, dict) and str(group.get("name") or "").strip()
        }
        proxy_names = {
            str(proxy.get("name"))
            for proxy in built.get("proxies", [])
            if isinstance(proxy, dict) and str(proxy.get("name") or "").strip()
        }
        return sorted(set(BUILTIN_TARGETS) | group_names | proxy_names), []
    except Exception:
        return sorted(fallback), ["策略组构建失败，已返回内置目标和当前节点名"]


def _draft_signature(draft: dict) -> str:
    canonical_json = json.dumps(
        draft,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _config_stats(built_config: dict | None, draft: dict) -> dict:
    if not isinstance(built_config, dict):
        return {
            "nodes": len(draft.get("proxies") or []),
            "groups": 0,
            "rules": len(draft.get("custom_rules") or []),
            "providers": len(draft.get("custom_rule_providers") or {}),
            "sources": len(draft.get("import_sources") or []),
        }
    return {
        "nodes": len(built_config.get("proxies") or []),
        "groups": len(built_config.get("proxy-groups") or []),
        "rules": len(built_config.get("rules") or []),
        "providers": len(built_config.get("rule-providers") or {}),
        "sources": len(draft.get("import_sources") or []),
    }


def _yaml_diff(draft_yaml: str, published_yaml: str) -> dict:
    draft_lines = draft_yaml.splitlines()
    published_lines = (published_yaml or "").splitlines()
    unified = "\n".join(
        difflib.unified_diff(
            published_lines,
            draft_lines,
            fromfile="published.yaml",
            tofile="draft.yaml",
            lineterm="",
        )
    )
    return {
        "has_changes": draft_yaml != (published_yaml or ""),
        "published": bool((published_yaml or "").strip()),
        "unified": unified,
        "lines": len(unified.splitlines()) if unified else 0,
    }


def _validation_checks(errors: list[str], warnings: list[str], mihomo_result) -> list[dict]:
    checks = [
        {"status": "error", "label": "结构检查", "detail": _safe_error_text(error)}
        for error in errors
    ]
    checks.extend(
        {"status": "warn", "label": "提示", "detail": _safe_error_text(warning)}
        for warning in warnings
    )
    status = getattr(mihomo_result, "status", "unknown")
    if status != "skipped":
        checks.append(
            {
                "status": "ok" if bool(getattr(mihomo_result, "ok", False)) else "error",
                "label": f"mihomo 内核校验（{status}）",
                "detail": _safe_error_text(getattr(mihomo_result, "message", "")),
            }
        )
    return checks


def _run_validation(draft: dict, published_yaml: str = "", normalization_meta: dict | None = None) -> dict:
    """验证、生成 YAML、计算 targets/signature/diff；不写入数据库。"""
    meta = normalization_meta or {"warnings": [], "errors": []}
    warnings = list(meta.get("warnings") or [])
    errors = list(meta.get("errors") or [])
    node_names = [str(proxy.get("name") or "") for proxy in draft.get("proxies") or []]
    duplicates = sorted({name for name in node_names if name and node_names.count(name) > 1})
    errors.extend(f"节点名称重复：{name}" for name in duplicates)

    built_config = None
    draft_yaml = ""
    mihomo_result = type(
        "ValidationResult",
        (),
        {"status": "skipped", "ok": True, "message": "未启用 mihomo 校验"},
    )()
    try:
        built_config = build_config(
            draft.get("proxies") or [],
            draft.get("global_config") or {},
            draft.get("custom_rules") or [],
            draft.get("custom_rule_providers") or {},
            draft.get("selected_rule_type") or DEFAULT_RULE_TYPE,
        )
        draft_yaml = build_yaml(built_config)
        config_errors, config_warnings = validate_config(
            built_config,
            allow_no_match=is_no_base_rule_type(draft.get("selected_rule_type")),
        )
        errors.extend(config_errors)
        warnings.extend(config_warnings)
        mihomo_result = validate_with_mihomo(draft_yaml)
    except Exception:
        errors.append("配置生成失败，请检查节点、规则和全局设置")
        warnings.append("配置生成阶段发生错误，未返回内部异常详情")

    mihomo_ok = bool(getattr(mihomo_result, "ok", False))
    mihomo_status = getattr(mihomo_result, "status", "skipped")
    if mihomo_status == "skipped":
        mihomo_ok = True
    ok = not errors and mihomo_ok
    targets, target_warnings = _safe_targets_for_draft(draft)
    warnings.extend(target_warnings)
    checks = _validation_checks(errors, warnings, mihomo_result)
    stats = _config_stats(built_config, draft)
    publish_diff = _yaml_diff(draft_yaml, published_yaml)
    return {
        "ok": ok,
        "checks": checks,
        "warnings": warnings,
        "stats": stats,
        "statistics": dict(stats),
        "mihomo": {
            "status": mihomo_status,
            "ok": bool(mihomo_ok),
            "message": _safe_error_text(getattr(mihomo_result, "message", "")),
        },
        "yaml": draft_yaml,
        "draft_signature": _draft_signature(draft),
        "all_targets": targets,
        # `publish_diff` 是 V2 canonical key；`diff` 保留给旧客户端。
        "publish_diff": publish_diff,
        "diff": publish_diff,
        "config": copy.deepcopy(draft),
        "_built_config": built_config,
        "_errors": errors,
    }


def _public_validation(data: dict) -> dict:
    return {key: value for key, value in data.items() if not key.startswith("_")}


def _subscription_data(saved_config: dict) -> dict:
    token = str(saved_config.get("token") or "")
    published = saved_config.get("published_at") or ""
    return {
        "token": token,
        "url": f"{get_public_base_url()}/sub/{token}" if token else "",
        "published_at": format_beijing_time(published),
        "published_at_raw": published,
        "validation_status": saved_config.get("validation_status", "unknown"),
        "draft_validation_status": saved_config.get("draft_validation_status", "unknown"),
        "has_published": bool((saved_config.get("final_yaml") or "").strip()),
        "status": "published" if bool((saved_config.get("final_yaml") or "").strip()) else "draft",
    }


def _publish_summary(saved_config: dict, subscription: dict | None = None) -> dict:
    subscription = subscription or _subscription_data(saved_config)
    return {
        "status": subscription["status"],
        "published_at": subscription["published_at"],
        "published_at_raw": subscription["published_at_raw"],
        "validation_status": subscription["validation_status"],
        "draft_validation_status": subscription["draft_validation_status"],
        "has_published": subscription["has_published"],
        "subscription_url": subscription["url"],
    }


def _bootstrap(user: dict, draft: dict, saved_config: dict | None = None, warnings: list[str] | None = None) -> dict:
    saved = saved_config or _load_saved_config(user)
    _materialize_private_urls_in_draft(user, draft, str(saved.get("token") or ""))
    targets, target_warnings = _safe_targets_for_draft(draft)
    all_warnings = list(warnings or []) + target_warnings
    subscription = _subscription_data(saved)
    try:
        built = build_config(
            draft["proxies"],
            draft["global_config"],
            draft["custom_rules"],
            draft["custom_rule_providers"],
            draft["selected_rule_type"],
        )
    except Exception:
        built = None
        all_warnings.append("当前草稿尚未能生成完整策略组，目标列表已降级")
    stats = _config_stats(built, draft)
    config = copy.deepcopy(draft)
    result = {
        "ok": True,
        "config": config,
        # 保留 V2 原型已经使用的扁平字段，避免前端升级期间断裂。
        **copy.deepcopy(config),
        "subscription": subscription,
        "provider_defaults": _provider_defaults(),
        "presets": {
            "full_client": FULL_CLIENT_DNS_PRESET,
            "openclash_router": OPENCLASH_ROUTER_SAFE_PRESET,
        },
        "dns_presets": {
            "full_client": FULL_CLIENT_DNS_PRESET,
            "openclash_router": OPENCLASH_ROUTER_SAFE_PRESET,
        },
        "node_form_schema": NODE_FORM_SCHEMA,
        "global_config_schema": GLOBAL_CONFIG_SCHEMA,
        "all_targets": targets,
        "counts": stats,
        "statistics": dict(stats),
        "draft_write_semantics": "last-full-draft-write-wins",
        "publish_summary": _publish_summary(saved, subscription),
        "warnings": all_warnings,
    }
    return result


@app.get("/api/config")
def api_get_config(request: Request):
    user = _require_api_user(request)
    saved = _load_saved_config(user)
    try:
        draft, meta = _normalize_draft(saved, saved)
    except Exception:
        draft = {
            "proxies": [],
            "global_config": _merged_global_config(None, saved.get("global_config")),
            "custom_rules": [],
            "custom_rule_providers": {},
            "selected_rule_type": DEFAULT_RULE_TYPE,
            "import_sources": [],
        }
        meta = {"warnings": ["历史草稿字段损坏，已返回安全默认配置"], "errors": []}
    _materialize_private_urls_in_draft(user, draft, str(saved.get("token") or ""))
    return _bootstrap(user, draft, saved, _draft_meta_warnings(meta))


@app.put("/api/config")
async def api_put_config(request: Request):
    user = _require_api_user(request)
    _require_api_csrf(request)
    body = await _read_json_body(request)
    user_id = int(user["id"])
    # Keep the complete provider lifecycle under one guard.  In particular,
    # cleanup in another process cannot remove a referenced version between
    # canonicalization and the draft DB write.
    with _ruleset_user_lock(user_id):
        current_user = _reload_ruleset_user(user_id)
        saved = _load_saved_config(current_user)
        draft, meta = _normalize_draft(body, saved)
        _materialize_private_urls_in_draft(current_user, draft, str(saved.get("token") or ""))
        save_user_draft(
            user_id,
            draft["proxies"],
            draft["global_config"],
            draft["custom_rules"],
            draft["custom_rule_providers"],
            draft["selected_rule_type"],
            draft["import_sources"],
            validation_status="unknown",
        )
        saved = _load_saved_config(current_user)
        _promote_referenced_pending_rulesets(user_id, draft)
        result = _bootstrap(current_user, draft, saved, _draft_meta_warnings(meta))
        result["saved_at"] = saved.get("updated_at", "")
        return result


@app.post("/api/import")
async def api_import(request: Request):
    user = _require_api_user(request)
    _require_api_csrf(request)
    body = await _read_json_body(request)
    mode = str((body.get("mode") or "yaml").strip().lower())
    content = str(body.get("content") or "")
    url = str(body.get("url") or "")
    name = str(body.get("name") or "").strip() or "未命名来源"
    if "existing_proxies" not in body:
        raise HTTPException(status_code=400, detail="existing_proxies 必须由请求明确提供")
    existing = body.get("existing_proxies")
    if not isinstance(existing, list) or any(not isinstance(item, dict) for item in existing):
        raise HTTPException(status_code=400, detail="existing_proxies 必须是节点对象数组")

    if mode in {"url", "remote", "subscription"}:
        if not url.strip():
            raise HTTPException(status_code=400, detail="请输入订阅链接")
        try:
            response_text, content_type = fetch_text_from_external_url(url.strip(), timeout=15)
            raw_content = normalize_subscription_content(response_text, content_type)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"获取订阅失败：{_safe_error_text(exc)}") from exc
        source_type = "url"
    elif mode in {"share", "share-link", "share_link"}:
        # 分享链接可以放在 content，也兼容旧前端错误地放在 url。
        share_text = "\n".join(item for item in (content, url) if item.strip())
        lines = [
            line.strip()
            for line in share_text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not lines:
            raise HTTPException(status_code=400, detail="请输入至少一条有效分享链接")
        try:
            parsed_links = [parse_share_link(line) for line in lines]
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"分享链接解析失败：{_safe_error_text(exc)}") from exc
        raw_content = yaml.dump(parsed_links, default_flow_style=False, allow_unicode=True, sort_keys=False)
        source_type = "share"
    else:
        if not content.strip():
            raise HTTPException(status_code=400, detail="请输入 YAML 内容")
        raw_content = content
        source_type = "yaml"

    try:
        input_proxies, import_warnings = parse_proxy_yaml(raw_content)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"节点解析失败：{_safe_error_text(exc)}") from exc

    existing_names = {
        str(proxy.get("name") or "")
        for proxy in existing
        if str(proxy.get("name") or "")
    }
    new_proxies = []
    skipped = []
    for proxy in input_proxies:
        name_value = str(proxy.get("name") or "")
        if name_value in existing_names:
            skipped.append(name_value)
            continue
        new_proxies.append(proxy)
        existing_names.add(name_value)

    tagged_proxies, source_dict = tag_import_source(name, source_type, new_proxies)
    return {
        "ok": True,
        "proxies": tagged_proxies,
        "source": source_dict,
        "skipped": skipped,
        "warnings": import_warnings,
    }


@app.post("/api/node/build")
async def api_node_build(request: Request):
    user = _require_api_user(request)
    _require_api_csrf(request)
    body = await _read_json_body(request)
    node_type = str(body.get("type") or "").strip().lower()
    fields = body.get("fields")
    if not isinstance(fields, dict):
        raise HTTPException(status_code=400, detail="fields 必须是对象")
    try:
        node = build_manual_node(node_type, fields)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=_safe_error_text(exc)) from exc
    requested_existing = body.get("existing_proxies")
    if requested_existing is not None and (
        not isinstance(requested_existing, list)
        or any(not isinstance(item, dict) for item in requested_existing)
    ):
        raise HTTPException(status_code=400, detail="existing_proxies 必须是节点对象数组")
    existing_proxies = requested_existing if requested_existing is not None else (
        _load_saved_config(user).get("proxies") or []
    )
    existing_names = {
        str(proxy.get("name") or "")
        for proxy in existing_proxies
        if isinstance(proxy, dict)
    }
    requested_name = str(node.get("name") or "").strip()
    if requested_name in existing_names:
        raise HTTPException(status_code=409, detail="节点名称已存在，请使用不同名称")
    return {"ok": True, "node": node}


def _ruleset_dir() -> str:
    default = "/app/ruleset" if os.name != "nt" else "ruleset"
    return os.getenv("RULESET_DIR", default)


def _ruleset_users_dir() -> Path:
    """Return the numeric per-user namespace root after symlink checks."""
    base_dir = Path(_ruleset_dir()).resolve()
    lexical_users_dir = base_dir / "users"
    if lexical_users_dir.is_symlink():
        raise ValueError("规则集用户根目录不能是符号链接")
    users_dir = lexical_users_dir.resolve()
    if base_dir not in users_dir.parents:
        raise ValueError("规则集用户根目录路径越界")
    return users_dir


def _ruleset_user_dir(user_id: int) -> Path:
    """Return the private physical namespace for one user's uploads.

    Physical upload files are isolated below ``users/<numeric-id>/`` so equal
    aliases never collide.  Existing drafts that reference the old global
    ``./ruleset/<alias>.<ext>`` path remain untouched by normalization and are
    intentionally outside this namespace.
    """
    users_dir = _ruleset_users_dir()
    lexical_user_dir = users_dir / str(int(user_id))
    if lexical_user_dir.is_symlink():
        raise ValueError("规则集用户目录不能是符号链接")
    user_dir = lexical_user_dir.resolve()
    if users_dir not in user_dir.parents:
        raise ValueError("规则集用户目录路径越界")
    return user_dir


_VERSIONED_RULESET_FILENAME_PATTERN = re.compile(
    r"^(?P<alias>[A-Za-z0-9][A-Za-z0-9._-]{0,63})--(?P<digest>[0-9a-f]{64})\.(?P<extension>yaml|txt|mrs)$"
)
_RULESET_TOMBSTONE_PATTERN = re.compile(r"^(?P<user_id>[0-9]+)-(?P<nonce>[0-9a-f]{32})$")
_RULESET_PENDING_MARKER_SUFFIX = ".pending.json"
_DEFAULT_RULESET_PENDING_TTL_SECONDS = 15 * 60


def _ruleset_pending_ttl_seconds() -> int:
    """Return the bounded lifetime of an upload not yet referenced by config."""
    raw = os.getenv("RULESET_PENDING_TTL_SECONDS")
    try:
        value = int(raw) if raw is not None else _DEFAULT_RULESET_PENDING_TTL_SECONDS
    except (TypeError, ValueError):
        value = _DEFAULT_RULESET_PENDING_TTL_SECONDS
    return max(1, min(value, 7 * 24 * 60 * 60))


def _ruleset_pending_root() -> Path:
    base_dir = Path(_ruleset_dir()).resolve()
    lexical_pending = base_dir / ".pending"
    if lexical_pending.is_symlink():
        raise ValueError("规则集待引用目录不能是符号链接")
    pending_root = lexical_pending.resolve()
    if base_dir not in pending_root.parents:
        raise ValueError("规则集待引用目录路径越界")
    return pending_root


def _ruleset_pending_user_dir(user_id: int) -> Path:
    pending_root = _ruleset_pending_root()
    lexical_user_dir = pending_root / str(int(user_id))
    if lexical_user_dir.is_symlink():
        raise ValueError("规则集待引用用户目录不能是符号链接")
    user_dir = lexical_user_dir.resolve()
    if pending_root not in user_dir.parents:
        raise ValueError("规则集待引用用户目录路径越界")
    return user_dir


def _pending_marker_path(user_id: int, filename: str) -> Path | None:
    if not _parse_versioned_ruleset_filename(filename):
        return None
    pending_dir = _ruleset_pending_user_dir(user_id)
    lexical = pending_dir / f"{filename}{_RULESET_PENDING_MARKER_SUFFIX}"
    try:
        resolved = lexical.resolve()
    except OSError:
        return None
    if lexical.parent != pending_dir.resolve() or resolved.parent != pending_dir.resolve() or lexical.is_symlink():
        return None
    return lexical


def _pending_ruleset_filenames(user_id: int) -> set[str]:
    """Read active upload reservations and discard expired/malformed markers."""
    pending_dir = _ruleset_pending_user_dir(user_id)
    if not pending_dir.exists():
        return set()
    if pending_dir.is_symlink() or not pending_dir.is_dir():
        raise OSError("规则集待引用用户目录不是安全目录")
    now = time.time()
    active: set[str] = set()
    for marker in pending_dir.iterdir():
        if marker.is_symlink() or not marker.is_file() or not marker.name.endswith(_RULESET_PENDING_MARKER_SUFFIX):
            continue
        filename = marker.name[: -len(_RULESET_PENDING_MARKER_SUFFIX)]
        remove = False
        try:
            with marker.open("r", encoding="utf-8") as handle:
                metadata = json.load(handle)
            expires_at = float(metadata.get("expires_at", 0))
            if metadata.get("filename") != filename or expires_at <= now:
                remove = True
            elif _parse_versioned_ruleset_filename(filename):
                active.add(filename)
            else:
                remove = True
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            remove = True
        if remove:
            try:
                marker.unlink()
            except OSError:
                pass
    return active


def _reserve_pending_ruleset(user_id: int, filename: str) -> None:
    """Atomically reserve an immutable upload until draft/publish references it."""
    marker = _pending_marker_path(user_id, filename)
    if marker is None:
        raise ValueError("规则集待引用文件名无效")
    pending_dir = marker.parent
    pending_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "filename": filename,
        "created_at": time.time(),
        "expires_at": time.time() + _ruleset_pending_ttl_seconds(),
    }
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            prefix=f".{filename}.",
            suffix=".tmp",
            dir=pending_dir,
            encoding="utf-8",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(metadata, temporary, ensure_ascii=False, separators=(",", ":"))
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, marker)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _release_pending_marker(user_id: int, filename: str) -> None:
    marker = _pending_marker_path(user_id, filename)
    if marker is None:
        return
    try:
        marker.unlink()
    except FileNotFoundError:
        pass


def _remove_pending_user_namespace(user_id: int) -> None:
    """Remove only one user's reservation namespace after DB deletion."""
    pending_dir = _ruleset_pending_user_dir(user_id)
    if not pending_dir.exists():
        return
    if pending_dir.is_symlink() or not pending_dir.is_dir():
        raise OSError("规则集待引用用户目录不是安全目录")
    shutil.rmtree(pending_dir)


def _promote_referenced_pending_rulesets(user_id: int, config: dict | None) -> None:
    """Release reservations that are now durable draft/published references."""
    user_dir = _ruleset_user_dir(user_id)
    referenced = _referenced_user_rulesets_for_config(user_id, config, user_dir)
    for filename in _pending_ruleset_filenames(user_id):
        target = _safe_user_ruleset_target(user_dir, filename)
        if target is None or not target.exists() or target in referenced:
            _release_pending_marker(user_id, filename)


def _user_ruleset_provider_path(user_id: int, filename: str) -> str:
    """Return the mihomo cache path for one versioned private file."""
    return f"./ruleset/users/{int(user_id)}/{filename}"


def _versioned_ruleset_filename(alias: str, extension: str, content: bytes) -> str:
    digest = hashlib.sha256(content).hexdigest()
    return f"{alias}--{digest}.{extension}"


def _parse_versioned_ruleset_filename(filename: str) -> tuple[str, str] | None:
    match = _VERSIONED_RULESET_FILENAME_PATTERN.fullmatch(str(filename or ""))
    if not match:
        return None
    return match.group("alias"), match.group("extension")


def _private_ruleset_filename(user_id: int, provider_path: str) -> str | None:
    normalized = str(provider_path or "").replace("\\", "/")
    prefix = f"./ruleset/users/{int(user_id)}/"
    if not normalized.startswith(prefix):
        return None
    filename = normalized[len(prefix):]
    if "/" in filename or not _parse_versioned_ruleset_filename(filename):
        return None
    return filename


def _safe_user_ruleset_target(user_dir: Path, filename: str) -> Path | None:
    """Resolve one version filename without following an escaping symlink."""
    lexical = user_dir / filename
    try:
        resolved = lexical.resolve()
    except OSError:
        return None
    base = user_dir.resolve()
    if lexical.parent != base or resolved.parent != base or lexical.is_symlink():
        return None
    return resolved


def _user_ruleset_url(token: str, user_id: int, filename: str) -> str:
    return (
        f"{get_public_base_url()}/ruleset/user/"
        f"{quote(str(token), safe='')}/{int(user_id)}/{quote(filename, safe='')}"
    )


def _ruleset_storage_extension(format_value: str) -> str:
    """Map the public provider format to the canonical on-disk extension."""
    normalized = str(format_value or "").strip().lower()
    if normalized in RULESET_FORMAT_EXTENSIONS:
        return RULESET_FORMAT_EXTENSIONS[normalized]
    # Accept extension-shaped values for an idempotent delete call from older
    # clients, but always resolve to the same canonical extension used by
    # upload.  No path component is accepted here.
    extension_map = {
        "yaml": "yaml",
        "yml": "yaml",
        "txt": "txt",
        "text": "txt",
        "list": "txt",
        "mrs": "mrs",
    }
    if normalized in extension_map:
        return extension_map[normalized]
    raise ValueError("format 只能是 text、yaml 或 mrs")


def _ruleset_trash_dir() -> Path:
    base_dir = Path(_ruleset_dir()).resolve()
    lexical_trash_dir = base_dir / ".trash"
    if lexical_trash_dir.is_symlink():
        raise ValueError("规则集回收目录不能是符号链接")
    trash_dir = lexical_trash_dir.resolve()
    if base_dir not in trash_dir.parents:
        raise ValueError("规则集回收目录路径越界")
    return trash_dir


def _retry_ruleset_tombstones() -> list[str]:
    """Recover/delete tombstones and purge orphaned numeric user namespaces.

    Every decision is made after taking the user's cross-process lock and
    re-reading the database.  A database row wins over filesystem cleanup:
    valid users are never deleted, and a tombstone is restored only when its
    original namespace is absent.
    """
    pending: list[str] = []
    try:
        trash_dir = _ruleset_trash_dir()
    except ValueError:
        return []
    if trash_dir.is_dir() and not trash_dir.is_symlink():
        try:
            tombstones = list(trash_dir.iterdir())
        except OSError:
            tombstones = []
        for item in tombstones:
            match = _RULESET_TOMBSTONE_PATTERN.fullmatch(item.name)
            if not match:
                continue
            user_id = int(match.group("user_id"))
            try:
                with _ruleset_user_lock(user_id):
                    # Re-read the DB inside the guard.  Another process may
                    # have recreated or deleted the account since scanning.
                    db_user = get_user_by_id(user_id)
                    user_dir = _ruleset_user_dir(user_id)
                    if item.is_symlink() or not item.is_dir():
                        pending.append(item.name)
                        continue
                    if db_user is not None:
                        users_dir = _ruleset_users_dir()
                        if user_dir.exists() or user_dir.is_symlink():
                            # Never overwrite valid user data with a stale
                            # tombstone.  Leave it for an explicit retry.
                            pending.append(item.name)
                            continue
                        users_dir.mkdir(parents=True, exist_ok=True)
                        os.replace(item, user_dir)
                    else:
                        shutil.rmtree(item)
            except Exception:
                pending.append(item.name)

    # A process can die after the DB commit and before rename().  Reconcile
    # numeric user directories only when the database confirms the user is
    # gone; all other directories and all symlinks are left untouched.
    try:
        users_dir = _ruleset_users_dir()
    except ValueError:
        return pending
    if users_dir.is_dir() and not users_dir.is_symlink():
        try:
            orphan_candidates = list(users_dir.iterdir())
        except OSError:
            orphan_candidates = []
        for item in orphan_candidates:
            if not re.fullmatch(r"[0-9]+", item.name):
                continue
            if item.is_symlink() or not item.is_dir():
                continue
            user_id = int(item.name)
            try:
                with _ruleset_user_lock(user_id):
                    if get_user_by_id(user_id) is not None:
                        continue
                    moved = _move_user_ruleset_to_tombstone(user_id)
                    if moved is None:
                        continue
                    _orphan_user_dir, tombstone = moved
                    try:
                        shutil.rmtree(tombstone)
                    except OSError:
                        pending.append(tombstone.name)
            except Exception:
                pending.append(item.name)

    # Reservation markers live outside users/<id>.  Once the DB row is gone,
    # they are safe to remove in the same user guard; never touch a namespace
    # whose account still exists.
    try:
        pending_root = _ruleset_pending_root()
    except ValueError:
        pending_root = None
    if pending_root is not None and pending_root.is_dir() and not pending_root.is_symlink():
        try:
            pending_candidates = list(pending_root.iterdir())
        except OSError:
            pending_candidates = []
        for item in pending_candidates:
            if not re.fullmatch(r"[0-9]+", item.name) or item.is_symlink() or not item.is_dir():
                continue
            user_id = int(item.name)
            try:
                with _ruleset_user_lock(user_id):
                    if get_user_by_id(user_id) is None:
                        _remove_pending_user_namespace(user_id)
            except Exception:
                pending.append(item.name)
    return pending


def _move_user_ruleset_to_tombstone(user_id: int) -> tuple[Path, Path] | None:
    user_dir = _ruleset_user_dir(user_id)
    if not user_dir.exists():
        return None
    if user_dir.is_symlink() or not user_dir.is_dir():
        raise OSError("规则集用户目录不是安全目录")
    trash_dir = _ruleset_trash_dir()
    trash_dir.mkdir(parents=True, exist_ok=True)
    tombstone = (trash_dir / f"{int(user_id)}-{uuid.uuid4().hex}").resolve()
    if trash_dir not in tombstone.parents:
        raise ValueError("规则集回收文件路径越界")
    os.replace(user_dir, tombstone)
    return user_dir, tombstone


def _delete_user_with_rulesets(user_id: int, actor_id: int | None = None) -> bool:
    """Delete DB rows first, then detach and remove the user's file namespace.

    Once the DB transaction succeeds, the subscription token is invalid even
    if a process crashes before the filesystem rename.  Such an orphan is
    reclaimed by ``_retry_ruleset_tombstones`` on startup or admin actions.

    ``actor_id`` is rechecked after acquiring the target lock.  It is optional
    only for internal recovery tests/callers that already have no actor; all
    admin API and Streamlit entry points pass it explicitly.
    """
    with _ruleset_user_lock(user_id):
        if actor_id is not None:
            _reload_admin_actor_locked(actor_id)
        target = get_user_by_id(int(user_id))
        if target is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        if bool(target["is_admin"]):
            raise HTTPException(status_code=403, detail="管理员账号不能在这里删除")
        # DB-first is intentional: if this raises, no filesystem operation has
        # happened and the caller can safely retry without restoration logic.
        delete_regular_user(user_id)
        try:
            moved = _move_user_ruleset_to_tombstone(user_id)
        except Exception:
            return True
        try:
            _remove_pending_user_namespace(user_id)
        except Exception:
            # The account is already gone; leave the inaccessible reservation
            # namespace for the next tombstone/orphan retry.
            return True
        if moved is None:
            return False
        _user_dir, tombstone = moved
        try:
            shutil.rmtree(tombstone)
            return False
        except Exception:
            return True


def _ruleset_user_usage(user_dir: Path) -> tuple[int, int]:
    if not user_dir.is_dir():
        return 0, 0
    total_bytes = 0
    file_count = 0
    for item in user_dir.iterdir():
        if not item.is_file():
            continue
        try:
            total_bytes += item.stat().st_size
        except OSError:
            continue
        file_count += 1
    return total_bytes, file_count


def _referenced_user_rulesets_from_providers(
    user_id: int,
    providers: object,
    user_dir: Path,
) -> set[Path]:
    """Resolve only versioned providers in one current-user namespace."""
    referenced: set[Path] = set()
    if not isinstance(providers, dict):
        return referenced
    for provider in providers.values():
        if not isinstance(provider, dict):
            continue
        filename = _private_ruleset_filename(user_id, str(provider.get("path") or ""))
        if filename:
            target = _safe_user_ruleset_target(user_dir, filename)
            if target is not None:
                referenced.add(target)
    return referenced


def _referenced_user_rulesets(user_id: int, draft: dict | None, user_dir: Path) -> set[Path]:
    providers = (draft or {}).get("custom_rule_providers") if isinstance(draft, dict) else {}
    return _referenced_user_rulesets_from_providers(user_id, providers, user_dir)


def _all_user_ruleset_files(user_dir: Path) -> set[Path]:
    """Return a conservative keep-set when a published document is unreadable."""
    if not user_dir.is_dir():
        return set()
    return {
        item.resolve()
        for item in user_dir.iterdir()
        if item.is_file() and not item.is_symlink()
    }


def _referenced_user_rulesets_from_yaml(user_id: int, final_yaml: str, user_dir: Path) -> set[Path]:
    if not str(final_yaml or "").strip():
        return set()
    try:
        loaded = yaml.safe_load(final_yaml)
    except Exception:
        # Never delete a published version merely because an older YAML is
        # temporarily unreadable; the next successful publish can reclaim it.
        return _all_user_ruleset_files(user_dir)
    if not isinstance(loaded, dict):
        return _all_user_ruleset_files(user_dir)
    return _referenced_user_rulesets_from_providers(user_id, loaded.get("rule-providers"), user_dir)


def _referenced_user_rulesets_for_config(user_id: int, config: dict | None, user_dir: Path) -> set[Path]:
    config = config if isinstance(config, dict) else {}
    return (
        _referenced_user_rulesets(user_id, config, user_dir)
        | _referenced_user_rulesets_from_yaml(user_id, str(config.get("final_yaml") or ""), user_dir)
    )


def _cleanup_unreferenced_user_rulesets(
    user_id: int,
    config: dict | None,
    *,
    strict: bool = False,
) -> list[Path]:
    """Remove stale files from one user's namespace only.

    This is intentionally called while the per-user upload lock is held.  It
    cleans failed/abandoned versions before the next quota check, but retains
    every version referenced by either the saved draft or published YAML.
    """
    user_dir = _ruleset_user_dir(user_id)
    referenced = _referenced_user_rulesets_for_config(user_id, config, user_dir)
    # An upload response is intentionally a short-lived reservation window:
    # the browser still has to PUT the provider into the draft.  Keep those
    # immutable files across a concurrent publish cleanup, but release the
    # marker as soon as the reference becomes durable.  Expired markers are
    # removed by _pending_ruleset_filenames and become eligible below.
    for filename in _pending_ruleset_filenames(user_id):
        target = _safe_user_ruleset_target(user_dir, filename)
        if target is None or not target.exists():
            _release_pending_marker(user_id, filename)
            continue
        if target in referenced:
            _release_pending_marker(user_id, filename)
            continue
        referenced.add(target)
    if not user_dir.is_dir():
        return []
    removed: list[Path] = []
    failures: list[OSError] = []
    for item in user_dir.iterdir():
        if not item.is_file() or item.resolve() in referenced:
            continue
        try:
            item.unlink()
        except OSError as exc:
            failures.append(exc)
            continue
        removed.append(item)
    if strict and failures:
        raise OSError("部分旧规则集版本清理失败") from failures[0]
    return removed


def _write_user_ruleset_atomic(user_id: int, filename: str, content: bytes) -> Path:
    """Write one immutable version atomically and enforce per-user quotas."""
    parsed = _parse_versioned_ruleset_filename(filename)
    if not parsed:
        raise ValueError("规则集版本文件名无效")
    alias, _extension = parsed
    user_dir = _ruleset_user_dir(user_id)
    user_dir.mkdir(parents=True, exist_ok=True)
    target = _safe_user_ruleset_target(user_dir, filename)
    if target is None:
        raise ValueError("规则集文件路径越界")
    if target.exists():
        if target.is_file() and target.read_bytes() == content:
            return target
        raise ValueError("规则集版本文件冲突")
    total_bytes, file_count = _ruleset_user_usage(user_dir)
    new_total = total_bytes + len(content)
    new_count = file_count + 1
    if new_total > MAX_RULESET_USER_BYTES:
        raise ValueError(f"该用户规则集总大小超过 {MAX_RULESET_USER_BYTES} bytes 配额")
    if new_count > MAX_RULESET_USER_FILES:
        raise ValueError(f"该用户规则集文件数超过 {MAX_RULESET_USER_FILES} 个配额")

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{alias}.",
            suffix=".tmp",
            dir=user_dir,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, target)
        temporary_path = None
        return target
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _ruleset_format_from_extension(extension: str) -> str:
    extension = extension.lower()
    if extension in {"yaml", "yml"}:
        return "yaml"
    if extension in {"mrs"}:
        return "mrs"
    return "text"


@app.post("/api/ruleset/test-url")
async def api_ruleset_test_url(request: Request):
    _require_api_user(request)
    _require_api_csrf(request)
    body = await _read_json_body(request)
    url = str(body.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url 不能为空")
    try:
        # fetch_text_from_external_url 内部完成 URL/DNS/重定向/大小防护；
        # 不在此处重复解析，避免测试替身和真实请求出现两次 DNS 查询。
        text, content_type = fetch_text_from_external_url(url, timeout=15)
        normalize_subscription_content(text, content_type)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"规则集地址检查失败：{_safe_error_text(exc)}") from exc
    return {
        "ok": True,
        "url": url,
        "status": "ok",
        "reachable": True,
        "content_type": content_type,
        "size": len(text.encode("utf-8")),
    }


@app.post("/api/ruleset/upload")
async def api_ruleset_upload(
    request: Request,
    file: UploadFile,
    alias: str = Form(""),
    behavior: str = Form("classical"),
    format: str = Form(""),
    interval: str = Form("86400"),
    order: str = Form("追加"),
    target: str = Form("Proxy"),
):
    user = _require_api_user(request)
    _require_api_csrf(request)
    filename = str(file.filename or "")
    if not filename or "." not in filename:
        raise HTTPException(status_code=400, detail="文件名必须包含扩展名")
    filename_path = Path(filename)
    extension = filename_path.suffix.lower().lstrip(".")
    if extension not in RULESET_EXTENSIONS:
        raise HTTPException(status_code=400, detail="不支持的规则集文件扩展名")
    raw_alias = alias.strip() or filename_path.stem
    try:
        safe_alias = validate_ruleset_alias(raw_alias)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=_safe_error_text(exc)) from exc

    normalized_format = format.strip().lower() or _ruleset_format_from_extension(extension)
    if normalized_format not in RULESET_FORMATS:
        raise HTTPException(status_code=400, detail="format 只能是 text、yaml 或 mrs")
    path_extension = {"yaml": "yaml", "text": "txt", "mrs": "mrs"}[normalized_format]
    if behavior.strip().lower() not in RULESET_BEHAVIORS:
        raise HTTPException(status_code=400, detail="不支持的规则集 behavior")
    normalized_order = order.strip() or "追加"
    if normalized_order not in RULESET_ORDERS:
        raise HTTPException(status_code=400, detail="不支持的规则集 order")
    if normalized_order in {"prepend"}:
        normalized_order = "优先 (覆盖)"
    elif normalized_order in {"append", "默认 (追加)"}:
        normalized_order = "追加"
    try:
        interval_seconds = int(interval)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="interval 必须是正整数秒") from exc
    if interval_seconds < 1 or interval_seconds > 31_536_000:
        raise HTTPException(status_code=400, detail="interval 必须在 1 秒到 365 天之间")
    normalized_target = target.strip()
    if not normalized_target or len(normalized_target) > 128:
        raise HTTPException(status_code=400, detail="target 不能为空且不能超过 128 个字符")
    if normalized_target == "no-resolve":
        raise HTTPException(status_code=400, detail="no-resolve 只能作为规则修饰符，不能作为目标策略")

    try:
        file_content = file.file.read(MAX_RULESET_UPLOAD_BYTES + 1)
    except OSError as exc:
        raise HTTPException(status_code=400, detail="读取规则集文件失败") from exc
    if len(file_content) > MAX_RULESET_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="规则集文件超过 4MB")

    user_id = int(user["id"])
    versioned_filename = _versioned_ruleset_filename(safe_alias, path_extension, file_content)
    saved = None
    try:
        # 只清理 draft 与 published 都未引用的版本，再在同一把锁内完成
        # 配额检查和原子写入；旧版本不会因同 alias 上传而被覆盖。
        with _ruleset_user_lock(user_id):
            # The auth session was checked before multipart parsing.  Re-read
            # the row after waiting for the lifecycle guard so a request that
            # raced account deletion cannot recreate config or write files.
            user = _reload_ruleset_user(user_id)
            saved = _load_saved_config(user)
            _cleanup_unreferenced_user_rulesets(user_id, saved)
            _write_user_ruleset_atomic(user_id, versioned_filename, file_content)
            # Keep the immutable version alive until the follow-up PUT/validate
            # has committed the provider reference.  This marker is atomic and
            # lives outside the user file namespace, so a publish cleanup in a
            # second process cannot mistake the upload for an orphan.
            _reserve_pending_ruleset(user_id, versioned_filename)
    except ValueError as exc:
        if "配额" in str(exc):
            raise HTTPException(status_code=413, detail=_safe_error_text(exc)) from exc
        raise HTTPException(status_code=400, detail="规则集文件路径或写入失败") from exc
    except OSError as exc:
        raise HTTPException(status_code=400, detail="规则集文件路径或写入失败") from exc

    provider = {
        "type": "http",
        "behavior": behavior.strip().lower(),
        "format": normalized_format,
        "path": _user_ruleset_provider_path(user_id, versioned_filename),
        "url": _user_ruleset_url(str((saved or {}).get("token") or ""), user_id, versioned_filename),
        "proxy": "DIRECT",
        "interval": interval_seconds,
        "order": normalized_order,
        "target": normalized_target,
    }
    return {
        "ok": True,
        "name": safe_alias,
        "alias": safe_alias,
        "path": provider["path"],
        "provider": provider,
        # 同时提供复数 canonical 字段，前端可以直接合并到草稿而无需
        # 猜测响应字段名；保留 singular 别名兼容旧原型。
        "custom_rule_providers": {safe_alias: provider},
        "custom_rule_provider": {safe_alias: provider},
        "metadata": {
            "filename": filename_path.name,
            "versioned_filename": versioned_filename,
            "bytes": len(file_content),
            "behavior": provider["behavior"],
            "format": normalized_format,
            "interval": interval_seconds,
            "order": normalized_order,
            "target": normalized_target,
        },
    }


@app.post("/api/ruleset/delete")
async def api_ruleset_delete(request: Request):
    """Delete one unreferenced versioned file from the current user namespace."""
    user = _require_api_user(request)
    _require_api_csrf(request)
    body = await _read_json_body(request)
    user_id = int(user["id"])
    raw_path = str(body.get("path") or "")
    versioned_filename = _private_ruleset_filename(user_id, raw_path)
    if not versioned_filename:
        raise HTTPException(status_code=400, detail="只能删除当前用户的版本化规则集路径")
    try:
        with _ruleset_user_lock(user_id):
            current_user = _reload_ruleset_user(user_id)
            user_dir = _ruleset_user_dir(user_id)
            config = _load_saved_config(current_user)
            target = _safe_user_ruleset_target(user_dir, versioned_filename)
            if target is None:
                raise HTTPException(status_code=400, detail="规则集文件路径越界")
            references = _referenced_user_rulesets_for_config(user_id, config, user_dir)
            if target in references:
                raise HTTPException(status_code=409, detail="当前草稿或已发布配置仍引用该规则集版本")
            existed = target.is_file() or target.is_symlink()
            if existed:
                target.unlink()
    except HTTPException:
        raise
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail="规则集文件删除失败") from exc

    return {
        "ok": True,
        "filename": versioned_filename,
        "deleted": bool(existed),
        "path": _user_ruleset_provider_path(user_id, versioned_filename),
    }


@app.post("/api/validate")
async def api_validate(request: Request):
    user = _require_api_user(request)
    _require_api_csrf(request)
    # 校验必须消费请求中提交的完整 canonical draft；不再读取可能仍在
    # 防抖队列中的数据库草稿，避免 validate 与 publish 之间产生竞态。
    body = await _read_json_body(request)
    user_id = int(user["id"])
    # Hold the same guard through mihomo validation and draft persistence so
    # publish cleanup cannot remove a referenced version mid-check.
    with _ruleset_user_lock(user_id):
        current_user = _reload_ruleset_user(user_id)
        saved = _load_saved_config(current_user)
        draft, meta = _normalize_draft(body, saved)
        _materialize_private_urls_in_draft(current_user, draft, str(saved.get("token") or ""))
        result = _run_validation(draft, saved.get("final_yaml") or "", meta)
        status = result["mihomo"]["status"] if result["ok"] else "failed"
        message = result["mihomo"]["message"] if result["ok"] else "；".join(result.get("_errors") or result["warnings"])
        save_user_draft(
            user_id,
            draft["proxies"],
            draft["global_config"],
            draft["custom_rules"],
            draft["custom_rule_providers"],
            draft["selected_rule_type"],
            draft["import_sources"],
            validation_status=status,
            validation_message=_safe_error_text(message),
        )
        _promote_referenced_pending_rulesets(user_id, draft)
        return _public_validation(result)


@app.post("/api/publish")
async def api_publish(request: Request):
    user = _require_api_user(request)
    _require_api_csrf(request)
    # publish 与 validate 使用同一份完整请求载荷，不能回退到旧的数据库草稿。
    body = await _read_json_body(request)
    user_id = int(user["id"])
    # The guard deliberately spans read -> normalize/materialize -> mihomo
    # validation -> DB commit -> refreshed read -> physical cleanup.  There is
    # no nested lock here; all helpers below are lock-free by design.
    with _ruleset_user_lock(user_id):
        current_user = _reload_ruleset_user(user_id)
        saved = _load_saved_config(current_user)
        draft, meta = _normalize_draft(body, saved)
        _materialize_private_urls_in_draft(current_user, draft, str(saved.get("token") or ""))
        result = _run_validation(draft, saved.get("final_yaml") or "", meta)
        public_result = _public_validation(result)
        if not result["ok"]:
            validation_details = {
                key: public_result.get(key)
                for key in (
                    "checks",
                    "warnings",
                    "stats",
                    "statistics",
                    "mihomo",
                    "draft_signature",
                    "all_targets",
                )
            }
            publish_diff = {
                "has_changes": bool((public_result.get("diff") or {}).get("has_changes")),
                "published": bool((public_result.get("diff") or {}).get("published")),
                "lines": int((public_result.get("diff") or {}).get("lines") or 0),
            }
            validation_details["publish_diff"] = publish_diff
            validation_details["diff"] = publish_diff
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "配置未通过校验，无法发布",
                    "checks": public_result.get("checks") or [],
                    "validation": validation_details,
                    # 409 envelope 也在 details 顶层提供安全摘要，便于客户端
                    # 不依赖旧的 validation 嵌套结构读取 canonical key。
                    "publish_diff": validation_details["publish_diff"],
                    "diff": validation_details["diff"],
                },
            )

        yaml_text = result["yaml"]
        save_user_config_atomic(
            user_id,
            draft,
            yaml_text,
            validation_status=result["mihomo"]["status"],
            validation_message=result["mihomo"]["message"],
        )
        refreshed = _load_saved_config(current_user)
        _promote_referenced_pending_rulesets(user_id, draft)
        publish_warnings = list(result.get("warnings") or [])
        try:
            # DB 原子提交已经成功；清理旧版本是 best-effort，但仍在同一
            # 用户 guard 内执行，避免下一次上传/草稿写入穿透引用窗口。
            _cleanup_unreferenced_user_rulesets(user_id, refreshed, strict=True)
        except Exception:
            publish_warnings.append("旧规则集版本清理未完成，将在后续上传或启动时重试")
        subscription = _subscription_data(refreshed)
        response = _bootstrap(current_user, draft, refreshed, publish_warnings)
        response.update(
            {
                "ok": True,
                "subscription_url": subscription["url"],
                "subscription": subscription,
                "published_at": subscription["published_at"],
                "yaml": yaml_text,
                "draft_signature": result["draft_signature"],
                "publish_diff": result["publish_diff"],
                "diff": result["diff"],
                "checks": result["checks"],
                "warnings": publish_warnings,
                "stats": result["stats"],
                "statistics": result["statistics"],
                "mihomo": result["mihomo"],
            }
        )
        return response


@app.post("/api/token/reset")
def api_token_reset(request: Request):
    user = _require_api_user(request)
    _require_api_csrf(request)
    user_id = int(user["id"])
    # Account deletion and token rotation share the same cross-process guard.
    # Re-read the row after waiting so an authenticated request cannot mint a
    # token for an account deleted while it was parsing the request.
    with _ruleset_user_lock(user_id):
        current_user = _reload_ruleset_user(user_id)
        new_token = reset_subscription_token(user_id)
        refreshed = _load_saved_config(current_user)
    subscription = _subscription_data(refreshed)
    return {
        "ok": True,
        "token": new_token,
        "subscription_url": subscription["url"],
        "subscription": subscription,
        "publish_summary": _publish_summary(refreshed, subscription),
    }


@app.get("/api/users")
def api_users(request: Request):
    user = _require_api_user(request)
    if not bool(user.get("is_admin")):
        raise HTTPException(status_code=403, detail="需要管理员权限")
    rows = [
        {
            "id": row["id"],
            "username": row["username"],
            "is_admin": bool(row["is_admin"]),
            "is_enabled": bool(row["is_enabled"]),
        }
        for row in list_users()
    ]
    return {"ok": True, "users": rows}


def _require_api_admin(request: Request) -> dict:
    user = _require_api_user(request)
    if not bool(user.get("is_admin")):
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


def _toggle_user_with_admin(user_id: int, actor_id: int) -> bool:
    """Toggle one ordinary user's enabled state under its lifecycle guard."""
    with _ruleset_user_lock(user_id):
        _reload_admin_actor_locked(actor_id)
        target = get_user_by_id(int(user_id))
        if target is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        if bool(target["is_admin"]):
            raise HTTPException(status_code=403, detail="管理员账号不能在这里启停")
        new_enabled = not bool(target["is_enabled"])
        set_user_enabled(user_id, new_enabled)
        return new_enabled


@app.post("/api/users/{user_id}/toggle")
def api_user_toggle(request: Request, user_id: int):
    admin = _require_api_admin(request)
    _require_api_csrf(request)
    new_enabled = _toggle_user_with_admin(user_id, int(admin["id"]))
    return {"ok": True, "is_enabled": new_enabled}


@app.post("/api/users/{user_id}/reset-token")
def api_user_reset_token(request: Request, user_id: int):
    admin = _require_api_admin(request)
    _require_api_csrf(request)
    with _ruleset_user_lock(user_id):
        # Re-check both actor privileges and target lifecycle inside the same
        # user guard used by deletion.  A stale admin page must not rotate a
        # token after the target row has disappeared or been disabled.
        _reload_admin_actor_locked(int(admin["id"]))
        target = _reload_ruleset_user(user_id)
        token = reset_subscription_token(user_id)
        refreshed = _load_saved_config(target)
    subscription = _subscription_data(refreshed)
    return {
        "ok": True,
        "user_id": user_id,
        "token": token,
        "subscription_url": subscription["url"],
        "subscription": subscription,
    }


@app.post("/api/users/{user_id}/delete")
def api_user_delete(request: Request, user_id: int):
    admin = _require_api_admin(request)
    _require_api_csrf(request)
    _retry_ruleset_tombstones()
    try:
        cleanup_pending = _delete_user_with_rulesets(user_id, int(admin["id"]))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=_safe_error_text(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail="用户删除失败，规则集目录未完成安全处理") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=_safe_error_text(exc)) from exc
    return {
        "ok": True,
        "cleanup_pending": bool(cleanup_pending),
        "warning": "用户已删除，但规则集临时目录清理待重试" if cleanup_pending else "",
    }


@app.post("/api/users/{username}")
async def api_user_create(request: Request, username: str):
    _require_api_admin(request)
    _require_api_csrf(request)
    body = await _read_json_body(request)
    password = body.get("password")
    if not isinstance(password, str) or not password:
        raise HTTPException(status_code=400, detail="密码不能为空")
    is_admin = bool(body.get("is_admin", False))
    try:
        normalized_username = validate_new_user_credentials(username, password)
        created = create_user(normalized_username, password, is_admin=is_admin)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=_safe_error_text(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="创建用户失败") from exc
    return {
        "ok": True,
        "user": _api_user_safe_dict(dict(created)),
        "id": created["id"],
        "username": created["username"],
    }
