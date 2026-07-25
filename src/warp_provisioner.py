import base64
import os
import secrets
from datetime import datetime, timezone
from typing import Any

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class WarpProvisionError(RuntimeError):
    """只携带可安全展示和记录的 WARP 预制错误。"""


def _positive_float_env(name: str, default: float) -> float:
    try:
        return max(1.0, float(os.getenv(name, str(default))))
    except ValueError:
        return default


def _response_json(response: requests.Response, stage: str) -> dict[str, Any]:
    if not 200 <= response.status_code < 300:
        if response.status_code == 429:
            raise WarpProvisionError("WARP 服务请求过于频繁，请稍后重试")
        raise WarpProvisionError(f"WARP {stage}失败（HTTP {response.status_code}）")
    try:
        payload = response.json()
    except ValueError as exc:
        raise WarpProvisionError(f"WARP {stage}返回了无效 JSON") from exc
    if not isinstance(payload, dict):
        raise WarpProvisionError(f"WARP {stage}返回结构异常")
    return payload


def _extract_registration(payload: dict[str, Any]) -> tuple[str, str]:
    registration_id = str(payload.get("id") or "").strip()
    access_token = str(payload.get("token") or "").strip()
    if not registration_id or not access_token:
        raise WarpProvisionError("WARP 注册响应缺少必要字段")
    return registration_id, access_token


def _extract_server_public_key(payload: dict[str, Any]) -> str:
    config = payload.get("config")
    peers = config.get("peers") if isinstance(config, dict) else payload.get("peers")
    if not isinstance(peers, list) or not peers or not isinstance(peers[0], dict):
        raise WarpProvisionError("WARP MASQUE 响应缺少 peer")
    raw_key = peers[0].get("public_key") or peers[0].get("public-key")
    if not isinstance(raw_key, str) or not raw_key.strip():
        raise WarpProvisionError("WARP MASQUE 响应缺少服务端公钥")
    try:
        public_key = serialization.load_pem_public_key(raw_key.encode("ascii"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise WarpProvisionError("WARP MASQUE 服务端公钥格式错误") from exc
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise WarpProvisionError("WARP MASQUE 服务端公钥不是 P-256")
    return base64.b64encode(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")


def provision_warp_masque(session: requests.Session | None = None) -> dict[str, Any]:
    """为一个用户创建独立 consumer WARP 注册并切换到 MASQUE。

    注册 ID 和 Access Token 只在当前调用内存中使用，不写入数据库或日志。
    """
    if os.getenv("WARP_PROVISION_ENABLED", "true").strip().lower() in {
        "0",
        "false",
        "no",
        "off",
    }:
        raise WarpProvisionError("WARP MASQUE 自动预制当前未启用")

    api_base = os.getenv("WARP_API_BASE_URL", "https://api.cloudflareclient.com").rstrip("/")
    api_version = os.getenv("WARP_API_VERSION", "v0a4471").strip().strip("/")
    client_version = os.getenv("WARP_CLIENT_VERSION", "a-6.35-4471").strip()
    timeout = _positive_float_env("WARP_REQUEST_TIMEOUT_SECONDS", 15.0)
    headers = {
        "User-Agent": "WARP for Android",
        "CF-Client-Version": client_version,
        "Content-Type": "application/json",
        "Connection": "Keep-Alive",
    }
    client = session or requests.Session()
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    register_payload = {
        "key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "install_id": "",
        "fcm_token": "",
        "tos": now,
        "model": "PC",
        "serial_number": secrets.token_hex(8),
        "locale": "en_US",
        "warp_enabled": True,
        "type": "Android",
        "key_type": "curve25519",
        "tunnel_type": "wireguard",
    }

    try:
        response = client.post(
            f"{api_base}/{api_version}/reg",
            headers=headers,
            json=register_payload,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise WarpProvisionError("WARP 注册请求失败或超时") from exc
    registration_id, access_token = _extract_registration(
        _response_json(response, "注册")
    )

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    masque_payload = {
        "key": base64.b64encode(public_der).decode("ascii"),
        "key_type": "secp256r1",
        "tunnel_type": "masque",
        "name": f"ccg-{secrets.token_hex(8)}",
    }
    patch_headers = dict(headers)
    patch_headers["Authorization"] = f"Bearer {access_token}"
    try:
        response = client.patch(
            f"{api_base}/{api_version}/reg/{registration_id}",
            headers=patch_headers,
            json=masque_payload,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise WarpProvisionError("WARP MASQUE 切换请求失败或超时") from exc
    server_public_key = _extract_server_public_key(
        _response_json(response, "MASQUE 切换")
    )

    return {
        "name": os.getenv("WARP_PRESET_NAME", "预制masque").strip() or "预制masque",
        "type": "masque",
        "server": os.getenv("WARP_PRESET_SERVER", "saas.sin.fan").strip() or "saas.sin.fan",
        "port": 443,
        "private-key": base64.b64encode(private_der).decode("ascii"),
        "public-key": server_public_key,
        "udp": False,
        "network": "h3-l4proxy",
        "sni": "consumer-masque-proxy.cloudflareclient.com",
    }
