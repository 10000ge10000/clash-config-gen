import re
from dataclasses import dataclass, field
from typing import Any


BROWSER_CLIENT_FINGERPRINTS = {
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
}

CERTIFICATE_PIN_PATTERN = re.compile(r"^(?:[A-Fa-f0-9]{64}|(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2})$")
HOP_INTERVAL_RANGE_PATTERN = re.compile(r"^\s*(\d+)\s*-\s*(\d+)\s*$")
INTERNAL_PROXY_FIELD_PREFIX = "_"

PROTOCOL_REQUIRED_FIELDS = {
    "ss": {"name", "type", "server", "port", "cipher", "password"},
    "trojan": {"name", "type", "server", "port", "password"},
    "vmess": {"name", "type", "server", "port", "uuid", "alterId", "cipher"},
    "vless": {"name", "type", "server", "port", "uuid"},
    "hysteria2": {"name", "type", "server", "port", "password"},
    "tuic": {"name", "type", "server", "port", "uuid", "password"},
    "anytls": {"name", "type", "server", "port", "password"},
    "wireguard": {"name", "type", "server", "port", "ip", "private-key", "public-key"},
}


@dataclass
class NormalizationResult:
    proxy: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def normalize_proxy(proxy: dict[str, Any]) -> NormalizationResult:
    """统一清洗单个节点字段，所有导入、保存、订阅输出都必须复用这里。

    这里不做节点可连通性判断，只修正会导致 mihomo/OpenClash 直接拒绝
    加载的配置形态问题，并保留用户自定义扩展字段。
    """
    normalized = dict(proxy)
    warnings: list[str] = []
    errors: list[str] = []

    if "type" in normalized:
        normalized["type"] = str(normalized["type"]).strip().lower()
        if normalized["type"] == "hy2":
            normalized["type"] = "hysteria2"
            warnings.append("已将协议类型 hy2 规范化为 hysteria2")

    if "name" in normalized:
        normalized["name"] = str(normalized["name"]).strip()
    if "server" in normalized:
        normalized["server"] = str(normalized["server"]).strip()
    if "port" in normalized:
        try:
            normalized["port"] = int(normalized["port"])
        except Exception:
            errors.append("端口不是数字")

    if normalized.get("type") == "hysteria2" and "hop-interval" in normalized:
        hop_interval = _normalize_hysteria2_hop_interval(normalized.get("hop-interval"))
        if hop_interval is None:
            normalized.pop("hop-interval", None)
            warnings.append("已移除无法解析为正整数秒的 hop-interval")
        else:
            normalized["hop-interval"] = hop_interval

    fingerprint = normalized.get("fingerprint")
    if fingerprint is not None:
        raw_fingerprint = str(fingerprint).strip()
        lower_fingerprint = raw_fingerprint.lower()
        if lower_fingerprint == "none":
            normalized.pop("fingerprint", None)
            warnings.append("已移除 fingerprint=none")
        elif lower_fingerprint in BROWSER_CLIENT_FINGERPRINTS:
            if not normalized.get("client-fingerprint"):
                normalized["client-fingerprint"] = lower_fingerprint
            normalized.pop("fingerprint", None)
            warnings.append("已将 fingerprint 转换为 client-fingerprint，避免 mihomo 当作证书固定字段")
        elif not CERTIFICATE_PIN_PATTERN.fullmatch(raw_fingerprint):
            normalized.pop("fingerprint", None)
            warnings.append("已移除不符合 SHA256 证书固定格式的 fingerprint")

    client_fingerprint = normalized.get("client-fingerprint")
    if client_fingerprint is not None:
        raw_client_fingerprint = str(client_fingerprint).strip()
        if not raw_client_fingerprint or raw_client_fingerprint.lower() == "none":
            normalized.pop("client-fingerprint", None)
            warnings.append("已移除空 client-fingerprint")
        elif raw_client_fingerprint != client_fingerprint:
            normalized["client-fingerprint"] = raw_client_fingerprint

    errors.extend(validate_proxy_fields(normalized))
    return NormalizationResult(proxy=normalized, warnings=warnings, errors=errors)


def normalize_proxies(proxies: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    normalized_proxies: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    for proxy in proxies:
        result = normalize_proxy(proxy)
        name = result.proxy.get("name") or proxy.get("name") or "未命名节点"
        normalized_proxies.append(result.proxy)
        warnings.extend(f"节点 {name}: {warning}" for warning in result.warnings)
        errors.extend(f"节点 {name}: {error}" for error in result.errors)
    return normalized_proxies, warnings, errors


def normalize_proxies_for_mihomo(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_proxies, _warnings, _errors = normalize_proxies(proxies)
    return normalized_proxies


def strip_internal_proxy_metadata(proxy: dict[str, Any]) -> dict[str, Any]:
    """移除仅供管理界面使用的来源、原名等内部字段。"""
    return {
        key: value
        for key, value in proxy.items()
        if not str(key).startswith(INTERNAL_PROXY_FIELD_PREFIX)
    }


def normalize_proxy_for_mihomo(proxy: dict[str, Any]) -> dict[str, Any]:
    return normalize_proxy(proxy).proxy


def _normalize_hysteria2_hop_interval(value: Any) -> int | None:
    """把 Hysteria2 端口跳跃间隔收敛为 OpenClash/mihomo 可解析的整数秒。

    部分订阅源或旧版表单会写出 `5-25` 这种范围。当前 OpenClash 使用的
    mihomo 配置解析器会把 `hop-interval` 按整数读取，范围字符串会直接导致
    内核启动失败。因此这里取范围左侧的最小间隔，保留“较快切换端口”的原始意图，
    同时保证输出配置可以被真实内核加载。
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, float):
        return int(value) if value.is_integer() and value > 0 else None

    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        seconds = int(text)
        return seconds if seconds > 0 else None

    range_match = HOP_INTERVAL_RANGE_PATTERN.fullmatch(text)
    if range_match:
        start = int(range_match.group(1))
        end = int(range_match.group(2))
        if start > 0 and end > 0 and start <= end:
            return start
    return None


def validate_proxy_fields(proxy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    proxy_type = str(proxy.get("type", "")).strip().lower()
    required_fields = PROTOCOL_REQUIRED_FIELDS.get(proxy_type, {"name", "type", "server", "port"})
    missing = [field for field in sorted(required_fields) if proxy.get(field) in (None, "")]
    if missing:
        errors.append(f"缺少必填字段: {', '.join(missing)}")

    port = proxy.get("port")
    if isinstance(port, int) and not 1 <= port <= 65535:
        errors.append("端口超出 1-65535")
    return errors
