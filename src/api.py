import yaml
from fastapi import FastAPI, HTTPException, Response

from storage import ensure_admin_from_env, get_config_by_token, health_snapshot, init_db


app = FastAPI(title="Clash-Config-Gen Subscription API")


@app.on_event("startup")
def startup() -> None:
    init_db()
    ensure_admin_from_env()


@app.get("/health")
def health_check():
    return health_snapshot()


@app.get("/sub/{token}")
def get_subscription(token: str):
    config = get_config_by_token(token)
    if not config:
        raise HTTPException(status_code=404, detail="订阅不存在、用户已禁用或 Token 已失效")

    final_yaml = config.get("final_yaml") or ""
    if not final_yaml.strip():
        raise HTTPException(status_code=409, detail="该用户尚未保存可用配置")

    try:
        yaml.safe_load(final_yaml)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"订阅 YAML 已损坏: {exc}") from exc

    return Response(
        content=final_yaml,
        media_type="application/x-yaml; charset=utf-8",
        headers={
            "Profile-Update-Interval": "24",
            "Subscription-Userinfo": "upload=0; download=0; total=0; expire=0",
        },
    )
