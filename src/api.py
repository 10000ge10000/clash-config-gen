import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

import yaml
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse

from auth import get_bool_env
from config_builder import DUSTINWIN_PROVIDERS_MAP
from config_builder import (
    build_subscription_headers,
    build_yaml,
    validate_config,
)
from diagnostics import build_subscription_diagnostics
from normalizer import normalize_proxies_for_mihomo
from ruleset_updater import get_ruleset_cache_path, start_ruleset_update_worker
from security import is_trusted_request_origin, request_client_ip, validate_csrf_token
from storage import (
    authenticate_user,
    create_auth_session,
    create_user,
    delete_regular_user,
    ensure_admin_from_env,
    get_config_by_token,
    get_public_base_url,
    get_user_by_auth_session,
    health_snapshot,
    init_db,
    recent_login_failure_counts,
    record_auth_audit_event,
    revoke_auth_session,
    validate_new_user_credentials,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    ensure_admin_from_env()
    start_ruleset_update_worker()
    yield


app = FastAPI(title="Clash-Config-Gen Subscription API", lifespan=lifespan)
AUTH_COOKIE_NAME = "clash_config_gen_session"
AUTH_COOKIE_DAYS = 30
AUTH_ASSET_PATH = Path(__file__).with_name("assets") / "auth-future-city.png"
V2_PREVIEW_CANDIDATES = [
    Path(__file__).with_name("design") / "v2-preview.html",
    Path(__file__).resolve().parent.parent / "design" / "v2-preview.html",
]


@app.get("/v2")
def v2_preview_page():
    for candidate in V2_PREVIEW_CANDIDATES:
        if candidate.is_file():
            return FileResponse(candidate, media_type="text/html; charset=utf-8")
    raise HTTPException(status_code=404, detail="V2 预览页不存在")


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
        response = _auth_redirect("登录尝试过于频繁，请稍后再试。")
        response.headers["Retry-After"] = str(window_seconds)
        return response

    user = authenticate_user(username, password)
    if not user:
        record_auth_audit_event("login", normalized_username, client_ip, False, "invalid_credentials")
        return _auth_redirect("用户名或密码错误，或账号已被禁用。")

    persistent = remember == "on"
    token = create_auth_session(
        int(user["id"]),
        days=AUTH_COOKIE_DAYS if persistent else 1,
    )
    response = _auth_redirect()
    _set_auth_cookie(response, token, persistent)
    record_auth_audit_event("login", str(user["username"]), client_ip, True, "authenticated")
    return response


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

    proxies = loaded_config.get("proxies") or []
    if isinstance(proxies, list):
        loaded_config["proxies"] = normalize_proxies_for_mihomo(
            [proxy for proxy in proxies if isinstance(proxy, dict)]
        )
        final_yaml = build_yaml(loaded_config)

    errors, _warnings = validate_config(loaded_config)
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
