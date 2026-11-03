import copy
import hashlib
import json
import logging
import re
import threading
from collections import OrderedDict
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from fastapi import FastAPI, Form, HTTPException, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException

from api_errors import _api_error_payload, _safe_error_text
from auth import get_bool_env
from auth_service import (
    AUTH_COOKIE_DAYS,
    AUTH_COOKIE_NAME,
    _auth_client_ip,
    _auth_redirect,
    _is_valid_auth_request,
    _positive_int_env,
    _register_rate_limit_window,
    _register_rate_limited,
    _request_session_binding,
    _set_auth_cookie,
    _try_login,
)
from config_builder import DEFAULT_RULE_TYPE, DUSTINWIN_PROVIDERS_MAP, is_no_base_rule_type
from config_builder import (
    build_rule_catalog,
    build_subscription_headers,
    build_yaml,
    validate_config,
)
from config_defaults import (
    FULL_CLIENT_DNS_PRESET,
    GLOBAL_CONFIG_SCHEMA,
    OPENCLASH_ROUTER_SAFE_PRESET,
)
from diagnostics import build_subscription_diagnostics
from draft_service import (
    _build_draft_config,
    _config_stats,
    _draft_meta_warnings,
    _merged_global_config,
    _normalize_draft,
    _provider_defaults,
    _public_validation,
    _run_validation,
    _safe_targets_for_draft,
)
from importers import (
    fetch_text_from_external_url,
    normalize_subscription_content,
    parse_proxy_yaml,
    parse_share_link,
    safe_ruleset_file_path,
    tag_import_source,
    validate_ruleset_alias,
)
from node_builder import NODE_FORM_SCHEMA, build_manual_node
from normalizer import normalize_proxies_for_mihomo
from ruleset_store import (
    MAX_RULESET_UPLOAD_BYTES,
    RULESET_BEHAVIORS,
    RULESET_EXTENSIONS,
    RULESET_FORMATS,
    RULESET_ORDERS,
    _cleanup_unreferenced_user_rulesets,
    _delete_user_with_rulesets,
    _has_any_user,
    _materialize_private_urls_in_draft,
    _materialize_private_urls_in_loaded_config,
    _parse_versioned_ruleset_filename,
    _private_ruleset_filename,
    _promote_referenced_pending_rulesets,
    _referenced_user_rulesets_for_config,
    _reload_admin_actor_locked,
    _reload_ruleset_user,
    _reserve_pending_ruleset,
    _retry_ruleset_tombstones,
    _ruleset_format_from_extension,
    _ruleset_user_dir,
    _ruleset_user_lock,
    _safe_user_ruleset_target,
    _toggle_user_with_admin,
    _user_ruleset_provider_path,
    _user_ruleset_url,
    _versioned_ruleset_filename,
    _write_user_ruleset_atomic,
)
from ruleset_updater import get_ruleset_cache_path, start_ruleset_update_worker
from security import create_csrf_token, csrf_session_binding, ensure_csrf_secret
from storage import (
    create_auth_session,
    create_user,
    delete_regular_user,
    ensure_admin_from_env,
    get_config_by_token,
    get_public_base_url,
    get_user_by_auth_session,
    get_user_config,
    health_snapshot,
    init_db,
    list_users,
    record_auth_audit_event,
    reset_subscription_token,
    revoke_auth_session,
    save_user_config_atomic,
    save_user_draft,
    validate_new_user_credentials,
)
from ui.time_display import format_beijing_time


LOGGER = logging.getLogger(__name__)

# 访问日志中的订阅 token 等同于订阅凭据：/sub/<token>、/ruleset/user/<token>/...
# 一律替换为 <redacted>。/sub/auth/、/sub/assets/ 是固定路由，不是 token。
_ACCESS_LOG_TOKEN_PATTERNS = (
    re.compile(r"(/sub/)(?!(?:auth|assets)(?:[/?#\s\"]|$))[^/?#\s\"]+"),
    re.compile(r"(/ruleset/user/)[^/?#\s\"]+"),
)


def _redact_access_log_text(value: str) -> str:
    for pattern in _ACCESS_LOG_TOKEN_PATTERNS:
        value = pattern.sub(r"\1<redacted>", value)
    return value


class _AccessLogTokenFilter(logging.Filter):
    """只改写 uvicorn.access 记录中的路径参数，不丢弃任何日志。"""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and args:
            record.args = tuple(
                _redact_access_log_text(item) if isinstance(item, str) else item
                for item in args
            )
        elif isinstance(args, dict) and args:
            record.args = {
                key: _redact_access_log_text(item) if isinstance(item, str) else item
                for key, item in args.items()
            }
        elif isinstance(record.msg, str):
            record.msg = _redact_access_log_text(record.msg)
        return True


def _install_access_log_filter() -> None:
    """幂等安装；uvicorn 的 dictConfig 不会移除 logger 上已有的 filter。"""
    access_logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(item, _AccessLogTokenFilter) for item in access_logger.filters):
        access_logger.addFilter(_AccessLogTokenFilter())


_install_access_log_filter()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _install_access_log_filter()
    if not get_public_base_url():
        raise RuntimeError(
            "未配置 PUBLIC_BASE_URL：订阅链接、规则集缓存地址和 Origin 校验都依赖对外访问地址，"
            "请在环境变量或 .env 中设置，例如 PUBLIC_BASE_URL=https://sub.example.com"
        )
    # CSRF_SECRET 缺失或仍是示例值时直接启动失败，而不是等到首个表单/API 请求才 500。
    ensure_csrf_secret()
    init_db()
    # 必须在 ensure_admin_from_env 之前判断：数据卷未挂载时新库会立刻被
    # 环境变量管理员“填充”，之后再判断就无法识别出这是一个空库。
    had_users = _has_any_user()
    ensure_admin_from_env()
    if had_users:
        _retry_ruleset_tombstones()
    else:
        LOGGER.warning("用户表为空（新数据库或数据卷未挂载），已跳过启动时的规则集孤儿清理")
    start_ruleset_update_worker()
    yield


# 关闭自动文档：CSP 不放行 Swagger UI 的 CDN 脚本，且无需对公网暴露接口结构。
app = FastAPI(
    title="Clash-Config-Gen Subscription API",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
AUTH_ASSET_PATH = Path(__file__).with_name("assets") / "auth-future-city.png"
# 本地开发时 design/ 位于仓库根目录；镜像内 src/ 与 design/ 平铺在同一工作目录。
V2_PREVIEW_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "design" / "index.html",
    Path(__file__).with_name("design") / "index.html",
]
UI_ASSET_DIR_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "design" / "assets",
    Path(__file__).with_name("design") / "assets",
]
# /ui/ 只放行这些静态文件，不接受路径参数，杜绝目录遍历。
UI_ASSET_MEDIA_TYPES = {
    "app.css": "text/css; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "favicon.svg": "image/svg+xml",
    "favicon.png": "image/png",
}

# /api 变更类请求统一使用这个 CSRF action，前端从 /api/session 领取。
API_CSRF_ACTION = "api"

# 主页脚本已外置到 /ui/app.js，script-src 不再放行内联脚本；页面仍有内联 style 属性，
# 因此 style-src 保留 'unsafe-inline'。生产在 Cloudflare 后会注入 Web Analytics
# beacon，所以放行 static.cloudflareinsights.com（脚本）与 cloudflareinsights.com（上报）。
# Referrer-Policy 必须保留同源 Referer，Origin/Referer 校验依赖它。
_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://static.cloudflareinsights.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self' https://cloudflareinsights.com; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "form-action 'self'"
)
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": _CONTENT_SECURITY_POLICY,
}


def _apply_security_headers(headers) -> None:
    """只在缺失时补齐安全头（含 HTTPS 下的 HSTS）；中间件与 500 处理器共用。"""
    for name, value in _SECURITY_HEADERS.items():
        headers.setdefault(name, value)
    if get_public_base_url().lower().startswith("https://"):
        headers.setdefault("Strict-Transport-Security", "max-age=31536000")


class _SecurityHeadersMiddleware:
    """纯 ASGI 中间件：只在响应头缺失时补齐，不改写路由自己设置的值。"""

    def __init__(self, asgi_app):
        self.app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                _apply_security_headers(MutableHeaders(scope=message))
            await send(message)

        await self.app(scope, receive, send_with_security_headers)


app.add_middleware(_SecurityHeadersMiddleware)


def _is_api_request(request: Request) -> bool:
    return request.url.path == "/api" or request.url.path.startswith("/api/")


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
    # Exception 处理器由最外层 ServerErrorMiddleware 调用，响应不经过安全头中间件，需在此显式补齐。
    if _is_api_request(request):
        response = JSONResponse(status_code=500, content={"ok": False, "error": "服务器内部错误"})
    else:
        response = JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
    try:
        _apply_security_headers(response.headers)
    except Exception:
        # 补头失败（如读取配置异常）时仍返回 500，避免在错误处理器里再次抛错。
        LOGGER.exception("500 响应补充安全头失败")
    return response


def _home_html_with_asset_versions(path: Path) -> str:
    """给 CSS/JS 链接加内容哈希：CDN 可能覆盖 no-cache 缓存数小时，旧样式会配上新页面。"""
    html = path.read_text(encoding="utf-8")
    for filename in UI_ASSET_MEDIA_TYPES:
        for asset_dir in UI_ASSET_DIR_CANDIDATES:
            asset = asset_dir / filename
            if asset.is_file():
                version = hashlib.sha256(asset.read_bytes()).hexdigest()[:12]
                html = html.replace(f'"/ui/{filename}"', f'"/ui/{filename}?v={version}"')
                break
    return html


@app.get("/v2")
def v2_preview_page():
    for candidate in V2_PREVIEW_CANDIDATES:
        if candidate.is_file():
            return Response(
                content=_home_html_with_asset_versions(candidate),
                media_type="text/html; charset=utf-8",
                # 主页随版本更新，必须每次向服务端确认，避免旧前端配新接口。
                headers={"Cache-Control": "no-cache"},
            )
    raise HTTPException(status_code=404, detail="V2 预览页不存在")


@app.get("/")
def root_v2_page():
    """FastAPI 根路径与 V2 页面保持同一生产入口，便于反代和健康探测。"""
    return v2_preview_page()


def _ui_asset_response(filename: str) -> FileResponse:
    """返回主页白名单静态资源；文件名只来自路由常量，不来自请求路径。"""
    media_type = UI_ASSET_MEDIA_TYPES[filename]
    for asset_dir in UI_ASSET_DIR_CANDIDATES:
        candidate = asset_dir / filename
        if candidate.is_file():
            return FileResponse(
                candidate,
                media_type=media_type,
                # 与主页同步更新，同样每次向服务端确认，避免新旧 HTML/JS 混用。
                headers={"Cache-Control": "no-cache"},
            )
    raise HTTPException(status_code=404, detail="主页静态资源不存在")


@app.get("/ui/app.css")
def ui_app_css():
    return _ui_asset_response("app.css")


@app.get("/ui/app.js")
def ui_app_js():
    return _ui_asset_response("app.js")


@app.get("/ui/favicon.svg")
def ui_favicon_svg():
    return _ui_asset_response("favicon.svg")


@app.get("/ui/favicon.png")
def ui_favicon_png():
    return _ui_asset_response("favicon.png")


@app.get("/health")
def health_check(request: Request):
    snapshot = health_snapshot()
    session_user = get_user_by_auth_session(request.cookies.get(AUTH_COOKIE_NAME, ""))
    if session_user and bool(session_user["is_admin"]):
        return snapshot
    # 未认证（含普通用户）只暴露探活所需的状态，不泄露数据库路径和用户规模。
    return {
        "status": snapshot.get("status", "ok"),
        "database_ok": True,
        "public_base_url_configured": bool(snapshot.get("public_base_url")),
    }


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
    if _register_rate_limited(client_ip):
        record_auth_audit_event("register_blocked", normalized_username, client_ip, False, "rate_limit")
        response = _auth_redirect("注册尝试过于频繁，请稍后再试。")
        response.headers["Retry-After"] = str(_register_rate_limit_window())
        return response
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


# 订阅正文缓存：键包含 token、用户、规则类型与已发布 YAML 的摘要，
# 重新发布（YAML 变化）或重置 token 后天然不再命中，无需显式失效。
# 只缓存校验通过的结果；错误路径每次都重新计算。
_SUBSCRIPTION_CACHE: "OrderedDict[tuple, tuple[str, int, int]]" = OrderedDict()
_SUBSCRIPTION_CACHE_GUARD = threading.Lock()
_SUBSCRIPTION_CACHE_MAX_ENTRIES = 32


def _subscription_cache_key(config: dict, final_yaml: str) -> tuple:
    return (
        str(config.get("token") or ""),
        int(config.get("user_id") or 0),
        str(config.get("selected_rule_type") or ""),
        hashlib.sha256(final_yaml.encode("utf-8")).hexdigest(),
    )


def _subscription_cache_get(key: tuple) -> tuple[str, int, int] | None:
    with _SUBSCRIPTION_CACHE_GUARD:
        cached = _SUBSCRIPTION_CACHE.get(key)
        if cached is not None:
            _SUBSCRIPTION_CACHE.move_to_end(key)
        return cached


def _subscription_cache_put(key: tuple, value: tuple[str, int, int]) -> None:
    with _SUBSCRIPTION_CACHE_GUARD:
        _SUBSCRIPTION_CACHE[key] = value
        _SUBSCRIPTION_CACHE.move_to_end(key)
        while len(_SUBSCRIPTION_CACHE) > _SUBSCRIPTION_CACHE_MAX_ENTRIES:
            _SUBSCRIPTION_CACHE.popitem(last=False)


def _load_subscription_yaml(final_yaml: str) -> dict:
    """解析已发布 YAML；详情只写日志，非 /api 响应只返回通用提示。"""
    try:
        loaded_config = yaml.safe_load(final_yaml)
    except Exception as exc:
        # YAML 异常文本会带出出错行原文（可能含节点密码），日志只记类型与位置。
        mark = getattr(exc, "problem_mark", None)
        position = f"line {mark.line + 1}, column {mark.column + 1}" if mark is not None else "unknown"
        LOGGER.warning("订阅 YAML 解析失败: %s at %s", type(exc).__name__, position)
        raise HTTPException(status_code=500, detail="订阅配置已损坏，请重新发布配置") from exc
    if not isinstance(loaded_config, dict):
        LOGGER.warning("订阅 YAML 顶层结构不是字典: %s", type(loaded_config).__name__)
        raise HTTPException(status_code=500, detail="订阅配置已损坏，请重新发布配置")
    return loaded_config


def _build_subscription_response(token: str, include_body: bool = True) -> Response:
    config = get_config_by_token(token)
    if not config:
        raise HTTPException(status_code=404, detail="订阅不存在、用户已禁用或 Token 已失效")

    final_yaml = config.get("final_yaml") or ""
    if not final_yaml.strip():
        raise HTTPException(status_code=409, detail="该用户尚未保存可用配置")

    cache_key = _subscription_cache_key(config, final_yaml)
    cached = _subscription_cache_get(cache_key)
    if cached is not None:
        body_yaml, proxy_count, group_count = cached
        return Response(
            content=body_yaml if include_body else "",
            media_type="application/x-yaml; charset=utf-8",
            headers=build_subscription_headers(proxy_count, group_count),
        )

    loaded_config = _load_subscription_yaml(final_yaml)

    materialized_urls = _materialize_private_urls_in_loaded_config(config, loaded_config)

    proxies = loaded_config.get("proxies") or []
    needs_rebuild = materialized_urls
    if isinstance(proxies, list):
        loaded_config["proxies"] = normalize_proxies_for_mihomo(
            [proxy for proxy in proxies if isinstance(proxy, dict)]
        )
        needs_rebuild = True

    errors, _warnings = validate_config(
        loaded_config,
        allow_no_match=is_no_base_rule_type(config.get("selected_rule_type")),
    )
    if errors:
        LOGGER.warning("订阅配置未通过可用性检查（user_id=%s）: %s", config.get("user_id"), _safe_error_text("; ".join(errors)))
        raise HTTPException(status_code=409, detail="该用户保存的配置未通过可用性检查，请在管理界面重新校验并发布")

    proxy_count = len(loaded_config.get("proxies") or [])
    group_count = len(loaded_config.get("proxy-groups") or [])
    if not include_body:
        # HEAD 只需要状态码与元信息头（节点/策略组计数），跳过 YAML 序列化。
        return Response(
            content="",
            media_type="application/x-yaml; charset=utf-8",
            headers=build_subscription_headers(proxy_count, group_count),
        )

    if needs_rebuild:
        final_yaml = build_yaml(loaded_config)
    _subscription_cache_put(cache_key, (final_yaml, proxy_count, group_count))
    return Response(
        content=final_yaml,
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
    loaded_config = _load_subscription_yaml(final_yaml)
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

MAX_DRAFT_BODY_BYTES = 2 * 1024 * 1024


def _require_api_user(request: Request) -> dict:
    """从会话 Cookie 解析当前用户；未登录返回 401。"""
    session_token = request.cookies.get(AUTH_COOKIE_NAME, "")
    user = get_user_by_auth_session(session_token)
    if not user:
        raise HTTPException(status_code=401, detail="未登录或会话已失效")
    return dict(user)


def _require_api_csrf(request: Request) -> None:
    """/api 变更请求统一校验 Origin + CSRF Token；失败返回 403。

    api 用途 token 绑定签发时的会话：多标签页换号后，旧标签页持有的旧账号 token
    配新账号 Cookie 会因摘要不一致被拒，避免把 A 的草稿写进 B。
    """
    token = request.headers.get("x-csrf-token", "")
    if not _is_valid_auth_request(request, token, API_CSRF_ACTION, binding=_request_session_binding(request)):
        raise HTTPException(status_code=403, detail="请求验证失败，请刷新页面后重试")


def _require_api_user_and_csrf(request: Request) -> dict:
    """会话（读库）+ CSRF 校验，供 async 路由经线程池调用。"""
    user = _require_api_user(request)
    _require_api_csrf(request)
    return user


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
        # 已登录：api token 绑定当前会话；未登录：auth token 不绑定。
        "csrf_token": (
            create_csrf_token(API_CSRF_ACTION, binding=csrf_session_binding(session_token))
            if user
            else create_csrf_token("auth")
        ),
        "allow_registration": get_bool_env("ALLOW_REGISTRATION", False),
    }


@app.post("/api/auth/login")
async def api_login(request: Request):
    # 只在事件循环里读取请求体；PBKDF2 与数据库访问放到线程池。
    body = await _read_json_body(request)
    return await run_in_threadpool(_api_login_sync, request, body)


def _api_login_sync(request: Request, body: dict) -> JSONResponse:
    client_ip = _auth_client_ip(request)
    username = body.get("username")
    password = body.get("password")
    csrf_token = body.get("csrf_token")
    if not isinstance(csrf_token, str):
        raise HTTPException(status_code=403, detail="请求验证失败，请刷新页面后重试")
    if not all(isinstance(value, str) for value in (username, password)):
        raise HTTPException(status_code=400, detail="username、password、csrf_token 必须是字符串")
    if not _is_valid_auth_request(request, csrf_token, "auth"):
        record_auth_audit_event("login_rejected", str(username or "").strip().lower(), client_ip, False, "csrf_or_origin")
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
            # 绑定本次登录新签发的会话（即将写入 Cookie 的 token）。
            "csrf_token": create_csrf_token(API_CSRF_ACTION, binding=csrf_session_binding(result["token"])),
        },
        status_code=200,
    )
    _set_auth_cookie(response, result["token"], result["persistent"])
    return response


@app.post("/api/auth/register")
async def api_register(request: Request):
    body = await _read_json_body(request)
    return await run_in_threadpool(_api_register_sync, request, body)


def _api_register_sync(request: Request, body: dict) -> JSONResponse:
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
        record_auth_audit_event("register_rejected", str(username or "").strip().lower(), client_ip, False, "csrf_or_origin")
        raise HTTPException(status_code=403, detail="请求验证失败，请刷新页面后重试")
    if not get_bool_env("ALLOW_REGISTRATION", False):
        record_auth_audit_event("register", str(username or "").strip().lower(), client_ip, False, "registration_disabled")
        raise HTTPException(status_code=403, detail="当前部署已关闭公开注册")
    if _register_rate_limited(client_ip):
        record_auth_audit_event("register_blocked", username.strip().lower(), client_ip, False, "rate_limit")
        raise HTTPException(
            status_code=429,
            detail="注册尝试过于频繁，请稍后再试",
            headers={"Retry-After": str(_register_rate_limit_window())},
        )

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
            "csrf_token": create_csrf_token(API_CSRF_ACTION, binding=csrf_session_binding(token)),
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


async def _read_json_body(request: Request) -> dict:
    """读取 JSON 请求体，区分空请求与格式错误，并统一限制请求大小。

    流式累加，超过上限立即 413，不会先把超大请求体整体读入内存。
    """
    too_large = HTTPException(status_code=413, detail="请求体超过 2MB，请精简节点后重试")
    declared_length = request.headers.get("content-length", "")
    if declared_length.strip().isdigit() and int(declared_length) > MAX_DRAFT_BODY_BYTES:
        raise too_large
    chunks: list[bytes] = []
    received = 0
    try:
        async for chunk in request.stream():
            received += len(chunk)
            if received > MAX_DRAFT_BODY_BYTES:
                break
            chunks.append(chunk)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="无法读取请求体") from exc
    if received > MAX_DRAFT_BODY_BYTES:
        raise too_large
    raw = b"".join(chunks)
    if not raw.strip():
        raise HTTPException(status_code=400, detail="请求体不能为空，必须提交 JSON")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="请求体不是有效 JSON") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON 顶层必须是对象")
    return body


def _load_saved_config(user: dict) -> dict:
    return get_user_config(int(user["id"]))


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


def _bootstrap(
    user: dict,
    draft: dict,
    saved_config: dict | None = None,
    warnings: list[str] | None = None,
    built_config: dict | None = None,
) -> dict:
    """``built_config`` 为调用方刚为同一草稿构建的配置时直接复用，避免重复 build。"""
    saved = saved_config or _load_saved_config(user)
    _materialize_private_urls_in_draft(user, draft, str(saved.get("token") or ""))
    built = built_config if isinstance(built_config, dict) else None
    if built is None:
        try:
            built = _build_draft_config(draft)
        except Exception:
            built = None
    targets, target_warnings = _safe_targets_for_draft(draft, built)
    all_warnings = list(warnings or []) + target_warnings
    subscription = _subscription_data(saved)
    if built is None:
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
        "rule_catalog": build_rule_catalog(),
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
    # async 路由只负责 await 读取请求体；读库、文件锁与配置构建在线程池执行。
    user = await run_in_threadpool(_require_api_user_and_csrf, request)
    body = await _read_json_body(request)
    return await run_in_threadpool(_api_put_config_sync, user, body)


def _api_put_config_sync(user: dict, body: dict) -> dict:
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
    await run_in_threadpool(_require_api_user_and_csrf, request)
    body = await _read_json_body(request)
    # 远程订阅抓取是阻塞网络 IO，必须离开事件循环。
    return await run_in_threadpool(_api_import_sync, body)


def _api_import_sync(body: dict) -> dict:
    mode = str((body.get("mode") or "yaml").strip().lower())
    content = str(body.get("content") or "")
    url = str(body.get("url") or "")
    name = str(body.get("name") or "").strip() or "未命名来源"
    if "existing_proxies" not in body:
        raise HTTPException(status_code=400, detail="existing_proxies 必须由请求明确提供")
    existing = body.get("existing_proxies")
    if not isinstance(existing, list) or any(not isinstance(item, dict) for item in existing):
        raise HTTPException(status_code=400, detail="existing_proxies 必须是节点对象数组")
    on_conflict = str(body.get("on_conflict") or "skip").strip().lower()
    if on_conflict not in {"skip", "replace"}:
        raise HTTPException(status_code=400, detail="on_conflict 只能是 skip 或 replace")

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
    replacing_proxies = []
    skipped = []
    seen_names = set()
    for proxy in input_proxies:
        name_value = str(proxy.get("name") or "")
        # 本次内容自身重名时只取第一个，覆盖模式也不例外。
        if name_value in seen_names:
            skipped.append(name_value)
            continue
        seen_names.add(name_value)
        if name_value in existing_names:
            if on_conflict == "replace":
                replacing_proxies.append(proxy)
            else:
                skipped.append(name_value)
            continue
        new_proxies.append(proxy)

    tagged_proxies, source_dict = tag_import_source(name, source_type, new_proxies + replacing_proxies)
    return {
        "ok": True,
        "proxies": tagged_proxies[: len(new_proxies)],
        # 同名节点由前端就地替换，节点顺序和策略组引用都不变。
        "replaced_proxies": tagged_proxies[len(new_proxies) :],
        "replaced": [str(proxy.get("name") or "") for proxy in replacing_proxies],
        "source": source_dict,
        "skipped": skipped,
        "warnings": import_warnings,
    }


@app.post("/api/node/build")
async def api_node_build(request: Request):
    user = await run_in_threadpool(_require_api_user_and_csrf, request)
    body = await _read_json_body(request)
    return await run_in_threadpool(_api_node_build_sync, user, body)


def _api_node_build_sync(user: dict, body: dict) -> dict:
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


@app.post("/api/ruleset/test-url")
async def api_ruleset_test_url(request: Request):
    await run_in_threadpool(_require_api_user_and_csrf, request)
    body = await _read_json_body(request)
    return await run_in_threadpool(_api_ruleset_test_url_sync, body)


def _api_ruleset_test_url_sync(body: dict) -> dict:
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
def api_ruleset_upload(
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

    # 本路由为同步 def（运行在线程池），这里同步读取临时文件与加文件锁不会阻塞事件循环。
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
    user = await run_in_threadpool(_require_api_user_and_csrf, request)
    body = await _read_json_body(request)
    return await run_in_threadpool(_api_ruleset_delete_sync, user, body)


def _api_ruleset_delete_sync(user: dict, body: dict) -> dict:
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
    user = await run_in_threadpool(_require_api_user_and_csrf, request)
    # 校验必须消费请求中提交的完整 canonical draft；不再读取可能仍在
    # 防抖队列中的数据库草稿，避免 validate 与 publish 之间产生竞态。
    body = await _read_json_body(request)
    # mihomo 子进程校验与用户文件锁都是阻塞操作，放到线程池执行。
    return await run_in_threadpool(_api_validate_sync, user, body)


def _api_validate_sync(user: dict, body: dict) -> dict:
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
    user = await run_in_threadpool(_require_api_user_and_csrf, request)
    # publish 与 validate 使用同一份完整请求载荷，不能回退到旧的数据库草稿。
    body = await _read_json_body(request)
    return await run_in_threadpool(_api_publish_sync, user, body)


def _api_publish_sync(user: dict, body: dict) -> dict:
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
        response = _bootstrap(current_user, draft, refreshed, publish_warnings, result.get("_built_config"))
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
    await run_in_threadpool(_require_api_admin_and_csrf, request)
    body = await _read_json_body(request)
    # 创建用户包含 PBKDF2 哈希，放到线程池执行。
    return await run_in_threadpool(_api_user_create_sync, username, body)


def _require_api_admin_and_csrf(request: Request) -> dict:
    admin = _require_api_admin(request)
    _require_api_csrf(request)
    return admin


def _api_user_create_sync(username: str, body: dict) -> dict:
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
