from typing import Any

import yaml

from clash_meta_gen import generate_proxy_groups


FAKE_IP_FILTER_LIST = [
    "+.services.googleapis.cn",
    "+.googleapis.cn",
    "*.lan",
    "*.localdomain",
    "*.example",
    "*.invalid",
    "*.localhost",
    "*.test",
    "*.local",
    "*.home.arpa",
    "*.direct",
    "time.windows.com",
    "geosite:cn",
]

SNIFFER_FORCE_DOMAIN = ["+.netflix.com", "+.nflxvideo.net", "+.amazonaws.com", "+.media.dssott.com"]
SNIFFER_SKIP_DOMAIN = ["Mijia Cloud", "dlg.io.mi.com", "+.oray.com", "+.sunlogin.net", "+.push.apple.com"]


def text_to_list(text: str) -> list[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def build_config(
    proxies: list[dict[str, Any]],
    global_config: dict[str, Any],
    custom_rules: list[str] | None = None,
    custom_rule_providers: dict[str, Any] | None = None,
    selected_rule_type: str = "自定义规则",
) -> dict[str, Any]:
    """生成最终 Clash/OpenClash 配置；API 和 Web UI 都应复用这套逻辑。"""
    custom_rules = custom_rules or []
    custom_rule_providers = custom_rule_providers or {}
    final_proxy_groups = generate_proxy_groups(proxies)

    final_config: dict[str, Any] = {
        "global": {
            "port": global_config.get("port", 7890),
            "socks-port": global_config.get("socks_port", 7891),
            "mixed-port": global_config.get("mixed_port", 7893),
            "allow-lan": global_config.get("allow_lan", True),
            "bind-address": global_config.get("bind_address", "*"),
            "mode": global_config.get("mode", "rule"),
            "log-level": global_config.get("log_level", "info"),
            "ipv6": global_config.get("ipv6_support", True),
            "external-controller": global_config.get("external_controller", "0.0.0.0:9090"),
            "find-process-mode": global_config.get("find_process_mode", "strict"),
        },
        "port": global_config.get("port", 7890),
        "socks-port": global_config.get("socks_port", 7891),
        "mixed-port": global_config.get("mixed_port", 7893),
        "allow-lan": global_config.get("allow_lan", True),
        "bind-address": global_config.get("bind_address", "*"),
        "mode": global_config.get("mode", "rule"),
        "log-level": global_config.get("log_level", "info"),
        "ipv6": global_config.get("ipv6_support", True),
        "external-controller": global_config.get("external_controller", "0.0.0.0:9090"),
        "find-process-mode": global_config.get("find_process_mode", "strict"),
        "proxies": proxies,
        "proxy-groups": final_proxy_groups,
    }

    if global_config.get("enable_tun", False):
        final_config["tun"] = {
            "enable": True,
            "stack": global_config.get("tun_stack", "mixed"),
            "device": global_config.get("tun_device", "utun"),
            "auto-route": global_config.get("tun_auto_route", True),
            "auto-detect-interface": global_config.get("tun_auto_detect_interface", True),
            "dns-hijack": ["any:53"] if global_config.get("tun_dns_hijack", True) else [],
        }

    if global_config.get("enable_dns", True):
        final_config["dns"] = {
            "enable": True,
            "listen": global_config.get("dns_listen", "0.0.0.0:7874"),
            "ipv6": global_config.get("dns_ipv6", True),
            "enhanced-mode": global_config.get("enhanced_mode", "fake-ip"),
            "fake-ip-range": global_config.get("fake_ip_range", "198.18.0.1/16"),
            "fake-ip-filter": FAKE_IP_FILTER_LIST,
            "default-nameserver": text_to_list(global_config.get("default_nameserver", "")),
            "nameserver": text_to_list(global_config.get("nameserver", "")),
            "fallback": text_to_list(global_config.get("fallback", "")),
            "fallback-filter": {"geoip": True, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"]},
        }
        policy = _parse_nameserver_policy(global_config.get("nameserver_policy", ""))
        if policy:
            final_config["dns"]["nameserver-policy"] = policy

    if global_config.get("secret"):
        final_config["secret"] = global_config["secret"]

    final_config["tcp-concurrent"] = global_config.get("tcp_concurrent", True)
    final_config["unified-delay"] = global_config.get("unified_delay", True)
    final_config["geodata-mode"] = global_config.get("geodata_mode", True)
    final_config["geodata-loader"] = global_config.get("geodata_loader", "standard")

    if global_config.get("enable_sniffer", True):
        final_config["sniffer"] = {
            "enable": True,
            "sniff": {
                "TLS": {"ports": [443]},
                "HTTP": {"ports": [80], "override-destination": True},
            },
            "force-domain": SNIFFER_FORCE_DOMAIN,
            "skip-domain": SNIFFER_SKIP_DOMAIN,
        }

    rules, rule_providers = build_rules(selected_rule_type, custom_rules, custom_rule_providers)
    if rule_providers:
        final_config["rule-providers"] = rule_providers
    final_config["rules"] = rules
    return final_config


def build_yaml(config: dict[str, Any]) -> str:
    return "# Generator: Clash-Config-Gen\n" + yaml.dump(
        config,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )


def validate_config(config: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    proxies = config.get("proxies") or []
    groups = config.get("proxy-groups") or []
    rules = config.get("rules") or []

    if not proxies:
        errors.append("Proxies 为空")
    if not any(str(rule).startswith("MATCH,") for rule in rules):
        errors.append("Rules 缺少 MATCH 兜底规则")

    proxy_names = [p.get("name") for p in proxies if isinstance(p, dict)]
    group_names = [g.get("name") for g in groups if isinstance(g, dict)]
    valid_targets = set(proxy_names + group_names + ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "no-resolve"])

    for group in groups:
        for target in group.get("proxies", []):
            if target not in valid_targets:
                warnings.append(f"策略组 '{group.get('name')}' 引用了不存在的节点/组: '{target}'")

    for rule in rules:
        parts = str(rule).split(",")
        if len(parts) >= 2:
            target = parts[-1]
            if target not in valid_targets and target != "no-resolve":
                warnings.append(f"规则 '{rule}' 指向了不存在的策略组: '{target}'")

    try:
        yaml.safe_load(build_yaml(config))
    except Exception as exc:
        errors.append(f"YAML 反解析失败: {exc}")

    return errors, warnings


def build_rules(
    selected_rule_type: str,
    custom_rules: list[str],
    custom_rule_providers: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    rule_providers: dict[str, Any] = {}
    if selected_rule_type == "lhie1规则":
        base_url = "https://testingcf.jsdelivr.net/gh/dler-io/Rules@main/Clash/Provider"
        providers_map = {
            "AdBlock": ("AdBlock", "AdBlock"),
            "HTTPDNS": ("HTTPDNS", "HTTPDNS"),
            "Special": ("Special", "DIRECT"),
            "PROXY": ("Proxy", "Proxy"),
            "Domestic": ("Domestic", "Domestic"),
            "Domestic IPs": ("Domestic%20IPs", "Domestic"),
            "LAN": ("LAN", "DIRECT"),
            "Netflix": ("Media/Netflix", "Netflix"),
            "YouTube": ("Media/YouTube", "Youtube"),
            "Microsoft": ("Microsoft", "Microsoft"),
            "AI Suite": ("AI%20Suite", "AI Suite"),
            "Apple": ("Apple", "Apple"),
            "Telegram": ("Telegram", "Telegram"),
            "Steam": ("Steam", "Steam"),
            "TikTok": ("TikTok", "TikTok"),
        }
        rule_list = [
            "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
            "DOMAIN-SUFFIX,services.googleapis.cn,Proxy",
        ]
        for name, (suffix, target) in providers_map.items():
            rule_providers[name] = {
                "type": "http",
                "behavior": "classical",
                "url": f"{base_url}/{suffix}.yaml",
                "path": f"./ruleset/{name.replace(' ', '_')}.yaml",
                "interval": 86400,
            }
            rule_list.append(f"RULE-SET,{name},{target}")
        rule_list.extend(["GEOIP,CN,Domestic,no-resolve", "MATCH,Others"])
    else:
        rule_list = [
            "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
            "DOMAIN-SUFFIX,services.googleapis.cn,Proxy",
            "DOMAIN-SUFFIX,google.com,Proxy",
            "DOMAIN-SUFFIX,youtube.com,Proxy",
            "GEOIP,CN,DIRECT,no-resolve",
            "MATCH,Proxy",
        ]

    provider_rules_prepend: list[str] = []
    provider_rules_append: list[str] = []
    for name, config in custom_rule_providers.items():
        provider = {
            "type": config.get("type", "http"),
            "behavior": config.get("behavior", "classical"),
            "path": config.get("path", f"./ruleset/{name}.yaml"),
            "interval": config.get("interval", 86400),
        }
        if provider["type"] == "http" and config.get("url"):
            provider["url"] = config["url"]
        if config.get("format"):
            provider["format"] = config["format"]
        rule_providers[name] = provider

        target = config.get("target", "Proxy")
        if config.get("order") == "优先 (覆盖)":
            provider_rules_prepend.append(f"RULE-SET,{name},{target}")
        else:
            provider_rules_append.append(f"RULE-SET,{name},{target}")

    preset_normal = [rule for rule in rule_list if not rule.startswith("MATCH,")]
    preset_match = [rule for rule in rule_list if rule.startswith("MATCH,")]
    final_rules = list(custom_rules) + provider_rules_prepend + preset_normal + provider_rules_append + preset_match
    if not any(rule.startswith("MATCH,") for rule in final_rules):
        final_rules.append("MATCH,Proxy")
    return final_rules, rule_providers


def _parse_nameserver_policy(raw_policy: str) -> dict[str, str]:
    policy: dict[str, str] = {}
    for line in (raw_policy or "").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            policy[key] = value
    return policy
