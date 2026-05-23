import yaml
from fastapi import FastAPI, HTTPException, Response

from config_builder import build_yaml, normalize_proxies_for_mihomo, validate_config
from storage import ensure_admin_from_env, get_config_by_token, health_snapshot, init_db


app = FastAPI(title="Clash-Config-Gen Subscription API")


@app.on_event("startup")
def startup() -> None:
    init_db()
    ensure_admin_from_env()


@app.get("/health")
def health_check():
    return health_snapshot()


def _build_subscription_response(token: str) -> Response:
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
        content=final_yaml,
        media_type="application/x-yaml; charset=utf-8",
        headers={
            "Profile-Update-Interval": "24",
            "Content-Disposition": 'inline; filename="clash-config.yaml"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Clash-Proxy-Count": str(proxy_count),
            "X-Clash-Proxy-Group-Count": str(group_count),
        },
    )


@app.get("/sub/{token}")
def get_subscription(token: str):
    return _build_subscription_response(token)


@app.get("/sub/{token}/config.yaml")
def get_subscription_yaml(token: str):
    return _build_subscription_response(token)
