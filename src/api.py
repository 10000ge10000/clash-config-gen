from pathlib import Path
from urllib.parse import quote

import yaml
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse

from auth import get_bool_env
from config_builder import DUSTINWIN_PROVIDERS_MAP
from config_builder import build_subscription_headers, build_yaml, validate_config
from diagnostics import build_subscription_diagnostics
from normalizer import normalize_proxies_for_mihomo
from ruleset_updater import get_ruleset_cache_path, start_ruleset_update_worker
from storage import (
    authenticate_user,
    create_auth_session,
    create_user,
    ensure_admin_from_env,
    get_config_by_token,
    health_snapshot,
    init_db,
    revoke_auth_session,
)


app = FastAPI(title="Clash-Config-Gen Subscription API")
AUTH_COOKIE_NAME = "clash_config_gen_session"
AUTH_COOKIE_DAYS = 30
AUTH_ASSET_PATH = Path(__file__).with_name("assets") / "auth-future-city.png"


@app.on_event("startup")
def startup() -> None:
    init_db()
    ensure_admin_from_env()
    start_ruleset_update_worker()


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
    username: str = Form(...),
    password: str = Form(...),
    remember: str = Form(""),
):
    user = authenticate_user(username, password)
    if not user:
        return _auth_redirect("用户名或密码错误，或账号已被禁用。")

    persistent = remember == "on"
    token = create_auth_session(
        int(user["id"]),
        days=AUTH_COOKIE_DAYS if persistent else 1,
    )
    response = _auth_redirect()
    _set_auth_cookie(response, token, persistent)
    return response


@app.post("/sub/auth/register")
def register(
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    if not get_bool_env("ALLOW_REGISTRATION", False):
        return _auth_redirect("当前部署已关闭公开注册，请联系管理员创建账号。")
    if password != password_confirm:
        return _auth_redirect("两次输入的密码不一致。")
    try:
        user = create_user(username, password, is_admin=False)
    except Exception as exc:
        return _auth_redirect(f"注册失败：{exc}")

    token = create_auth_session(int(user["id"]), days=AUTH_COOKIE_DAYS)
    response = _auth_redirect()
    _set_auth_cookie(response, token, remember=True)
    return response


@app.post("/sub/auth/logout")
def logout(request: Request):
    revoke_auth_session(request.cookies.get(AUTH_COOKIE_NAME, ""))
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
