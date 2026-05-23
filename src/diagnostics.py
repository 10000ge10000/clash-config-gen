from typing import Any


def build_subscription_diagnostics(config: dict[str, Any], loaded_config: dict[str, Any]) -> dict[str, Any]:
    proxies = loaded_config.get("proxies") or []
    groups = loaded_config.get("proxy-groups") or []
    rules = loaded_config.get("rules") or []
    if not isinstance(proxies, list):
        proxies = []
    if not isinstance(groups, list):
        groups = []
    if not isinstance(rules, list):
        rules = []

    return {
        "status": "ok",
        "user_id": config.get("user_id"),
        "updated_at": config.get("updated_at"),
        "validated_at": config.get("validated_at", ""),
        "validation_status": config.get("validation_status", "unknown"),
        "validation_message": config.get("validation_message", ""),
        "proxy_count": len(proxies),
        "proxy_group_count": len(groups),
        "rule_count": len(rules),
        "fingerprint_count": sum(1 for proxy in proxies if isinstance(proxy, dict) and "fingerprint" in proxy),
        "client_fingerprint_count": sum(1 for proxy in proxies if isinstance(proxy, dict) and "client-fingerprint" in proxy),
        "has_proxy_group": any(isinstance(group, dict) and group.get("name") == "Proxy" for group in groups),
        "has_match_rule": any(str(rule).startswith("MATCH,") for rule in rules),
    }
