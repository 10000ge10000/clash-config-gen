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

SOFT_ROUTER_FAKE_IP_FILTER_LIST = [
    "+.lan", "+.local", "+.localhost", "+.localdomain", "+.home.arpa", "+.test", "+.example", "+.invalid",
    "localhost", "msftconnecttest.com", "www.msftconnecttest.com", "msftncsi.com", "www.msftncsi.com",
    "detectportal.firefox.com", "time.apple.com", "time-ios.apple.com", "time1.apple.com", "time.windows.com",
    "time.nist.gov", "time.cloudflare.com", "time1.cloud.tencent.com", "ntp.aliyun.com", "ntp.tencent.com",
    "+.pool.ntp.org", "+.ntp.org.cn", "+.time.edu.cn", "short.weixin.qq.com", "long.weixin.qq.com",
    "dns.weixin.qq.com", "+.weixin.qq.com", "+.wechat.com", "+.wechatpay.com", "+.tenpay.com",
    "+.qpic.cn", "+.qlogo.cn", "+.gtimg.com", "+.gtimg.cn", "+.idqqimg.com", "stun.*.*", "stun.*.*.*",
    "+.srv.nintendo.net", "xbox.*.microsoft.com", "+.xboxlive.com", "+.steamcontent.com", "+.music.163.com",
    "+.126.net", "+.qqmusic.qq.com", "+.music.migu.cn", "+.mcdn.bilivideo.cn", "+.bilivideo.cn",
    "dlg.io.mi.com", "ot.io.mi.com", "+.mi.com", "+.xiaomi.com", "+.push.xiaomi.com", "+.cmbchina.com",
    "+.unionpay.com", "geosite:cn",
]

SNIFFER_FORCE_DOMAIN = [
    "+.youtube.com", "+.googlevideo.com", "+.ytimg.com", "+.ggpht.com",
    "+.netflix.com", "+.nflxvideo.net", "+.nflximg.net", "+.nflxso.net", "+.nflxext.com",
    "+.disneyplus.com", "+.dssott.com", "+.disney.com",
    "+.discord.com", "+.discord.gg", "+.discordapp.com", "+.discordapp.net",
    "+.telegram.org", "+.t.me", "+.twitter.com", "+.x.com", "+.twimg.com",
    "+.facebook.com", "+.fbcdn.net", "+.instagram.com", "+.cdninstagram.com",
]
SNIFFER_SKIP_DOMAIN = [
    "Mijia Cloud", "dlg.io.mi.com", "+.mi.com", "+.xiaomi.com", "+.push.xiaomi.com",
    "+.oray.com", "+.sunlogin.net", "+.xunlei.com", "courier.push.apple.com", "+.push.apple.com",
]
SNIFFER_SKIP_DST_ADDRESS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
]

LHIE1_PROVIDERS_MAP = {
    "AdBlock": ("AdBlock", "AdBlock"),
    "HTTPDNS": ("HTTPDNS", "HTTPDNS"),
    "Special": ("Special", "DIRECT"),
    "PROXY": ("Proxy", "Proxy"),
    "Domestic": ("Domestic", "Domestic"),
    "Domestic IPs": ("Domestic%20IPs", "Domestic"),
    "LAN": ("LAN", "DIRECT"),
    "Netflix": ("Media/Netflix", "Netflix"),
    "Spotify": ("Media/Spotify", "Spotify"),
    "YouTube": ("Media/YouTube", "Youtube"),
    "Max": ("Media/Max", "HBO Max"),
    "Bilibili": ("Media/Bilibili", "Bilibili"),
    "IQ": ("Media/IQ", "Asian TV"),
    "IQIYI": ("Media/IQIYI", "Asian TV"),
    "Letv": ("Media/Letv", "Asian TV"),
    "Netease Music": ("Media/Netease%20Music", "Asian TV"),
    "Tencent Video": ("Media/Tencent%20Video", "Asian TV"),
    "Youku": ("Media/Youku", "Asian TV"),
    "WeTV": ("Media/WeTV", "Global TV"),
    "ABC": ("Media/ABC", "Global TV"),
    "Abema TV": ("Media/Abema%20TV", "Asian TV"),
    "Amazon": ("Media/Amazon", "Global TV"),
    "Apple Music": ("Media/Apple%20Music", "Apple"),
    "Apple News": ("Media/Apple%20News", "Apple"),
    "Apple TV": ("Media/Apple%20TV", "Apple TV"),
    "Bahamut": ("Media/Bahamut", "Bahamut"),
    "BBC iPlayer": ("Media/BBC%20iPlayer", "Global TV"),
    "DAZN": ("Media/DAZN", "DAZN"),
    "Discovery Plus": ("Media/Discovery%20Plus", "Discovery Plus"),
    "Disney Plus": ("Media/Disney%20Plus", "Disney Plus"),
    "DMM": ("Media/DMM", "Asian TV"),
    "encoreTVB": ("Media/encoreTVB", "Global TV"),
    "F1 TV": ("Media/F1%20TV", "Global TV"),
    "Fox Now": ("Media/Fox%20Now", "Global TV"),
    "Fox+": ("Media/Fox%2B", "Asian TV"),
    "Hulu Japan": ("Media/Hulu%20Japan", "Asian TV"),
    "Hulu": ("Media/Hulu", "Global TV"),
    "JOOX": ("Media/JOOX", "Asian TV"),
    "KKBOX": ("Media/KKBOX", "Asian TV"),
    "KKTV": ("Media/KKTV", "Asian TV"),
    "Line TV": ("Media/Line%20TV", "Asian TV"),
    "myTV SUPER": ("Media/myTV%20SUPER", "Asian TV"),
    "Niconico": ("Media/Niconico", "Asian TV"),
    "Pandora": ("Media/Pandora", "Global TV"),
    "PBS": ("Media/PBS", "Global TV"),
    "Pornhub": ("Media/Pornhub", "Pornhub"),
    "Soundcloud": ("Media/Soundcloud", "Global TV"),
    "ViuTV": ("Media/ViuTV", "Asian TV"),
    "Telegram": ("Telegram", "Telegram"),
    "Crypto": ("Crypto", "Crypto"),
    "Discord": ("Discord", "Discord"),
    "Steam": ("Steam", "Steam"),
    "TikTok": ("TikTok", "TikTok"),
    "Speedtest": ("Speedtest", "Speedtest"),
    "PayPal": ("PayPal", "PayPal"),
    "Microsoft": ("Microsoft", "Microsoft"),
    "AI Suite": ("AI%20Suite", "AI Suite"),
    "Apple": ("Apple", "Apple"),
    "Google FCM": ("Google%20FCM", "Google FCM"),
    "Scholar": ("Scholar", "Scholar"),
    "miHoYo": ("miHoYo", "miHoYo"),
}


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

    for key, default in {
        "redir-port": global_config.get("redir_port"),
        "tproxy-port": global_config.get("tproxy_port"),
        "interface-name": global_config.get("interface_name"),
        "keep-alive-interval": global_config.get("keep_alive_interval"),
        "keep-alive-idle": global_config.get("keep_alive_idle"),
    }.items():
        if default not in (None, ""):
            final_config[key] = default

    if global_config.get("external_ui"):
        final_config["external-ui"] = global_config["external_ui"]
    if global_config.get("external_ui_name"):
        final_config["external-ui-name"] = global_config["external_ui_name"]
    if global_config.get("external_ui_url"):
        final_config["external-ui-url"] = global_config["external_ui_url"]

    if global_config.get("enable_tun", False):
        final_config["tun"] = {
            "enable": True,
            "stack": global_config.get("tun_stack", "mixed"),
            "device": global_config.get("tun_device", "utun"),
            "auto-route": global_config.get("tun_auto_route", True),
            "auto-detect-interface": global_config.get("tun_auto_detect_interface", True),
            "dns-hijack": text_to_list(global_config.get("tun_dns_hijack_value", "127.0.0.1:53")) if global_config.get("tun_dns_hijack", True) else [],
            "endpoint-independent-nat": global_config.get("tun_endpoint_independent_nat", True),
            "auto-redirect": global_config.get("tun_auto_redirect", False),
            "strict-route": global_config.get("tun_strict_route", False),
        }

    if global_config.get("enable_dns", True):
        is_desktop = global_config.get("is_desktop", True)
        final_config["dns"] = {
            "enable": True,
            "fake-ip-filter": SOFT_ROUTER_FAKE_IP_FILTER_LIST if global_config.get("openclash_preset", True) else FAKE_IP_FILTER_LIST,
        }
        # OpenClash 模式下仅生成精简 DNS 配置，其他字段由插件管理
        if is_desktop:
            final_config["dns"].update({
                "listen": global_config.get("dns_listen", "0.0.0.0:7874"),
                "ipv6": global_config.get("dns_ipv6", True),
                "enhanced-mode": global_config.get("enhanced_mode", "fake-ip"),
                "fake-ip-range": global_config.get("fake_ip_range", "198.18.0.1/16"),
                "default-nameserver": text_to_list(global_config.get("default_nameserver", "")),
                "nameserver": text_to_list(global_config.get("nameserver", "")),
            })
            if global_config.get("fake_ip_range6"):
                final_config["dns"]["fake-ip-range6"] = global_config["fake_ip_range6"]
            final_config["dns"]["respect-rules"] = global_config.get("dns_respect_rules", False)
            if global_config.get("fake_ip_filter_mode"):
                final_config["dns"]["fake-ip-filter-mode"] = global_config["fake_ip_filter_mode"]
            direct_nameserver = text_to_list(global_config.get("direct_nameserver", ""))
            if direct_nameserver:
                final_config["dns"]["direct-nameserver"] = direct_nameserver
            fallback = text_to_list(global_config.get("fallback", ""))
            if fallback:
                final_config["dns"]["fallback"] = fallback
                final_config["dns"]["fallback-filter"] = {"geoip": True, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"]}
            policy = _parse_nameserver_policy(global_config.get("nameserver_policy", ""))
            if policy:
                final_config["dns"]["nameserver-policy"] = policy
        else:
            # OpenClash 模式下仅保留必要的 DNS 字段
            final_config["dns"]["respect-rules"] = global_config.get("dns_respect_rules", True)

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
                "HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
                "QUIC": {"ports": [443, 8443]},
            },
            "override-destination": global_config.get("sniff_override_dest", False),
            "force-domain": SNIFFER_FORCE_DOMAIN,
            "skip-domain": SNIFFER_SKIP_DOMAIN,
            "parse-pure-ip": global_config.get("sniffer_parse_pure_ip", True),
            "force-dns-mapping": global_config.get("sniffer_force_dns_mapping", True),
            "skip-dst-address": SNIFFER_SKIP_DST_ADDRESS,
        }

    if global_config.get("profile_store_selected", True) or global_config.get("profile_store_fake_ip", True):
        final_config["profile"] = {
            "store-selected": global_config.get("profile_store_selected", True),
            "store-fake-ip": global_config.get("profile_store_fake_ip", True),
        }

    if global_config.get("ntp_enable", False):
        final_config["ntp"] = {
            "enable": True,
            "server": global_config.get("ntp_server", "time.apple.com"),
            "port": global_config.get("ntp_port", 123),
            "interval": global_config.get("ntp_interval", 30),
            "write-to-system": global_config.get("ntp_write_to_system", True),
        }

    auth = global_config.get("authentication", "")
    auth_list = text_to_list(auth)
    if auth_list:
        final_config["authentication"] = auth_list

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
        rule_list = [
            "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
            "DOMAIN-SUFFIX,services.googleapis.cn,Proxy",
        ]
        for name, (suffix, target) in LHIE1_PROVIDERS_MAP.items():
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
