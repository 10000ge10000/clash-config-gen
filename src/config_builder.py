import base64
import os
from typing import Any

import yaml

from clash_meta_gen import (
    DEFAULT_URL_TEST_INTERVAL,
    DEFAULT_URL_TEST_TOLERANCE,
    DEFAULT_URL_TEST_URL,
    generate_proxy_groups,
)
from normalizer import normalize_proxies_for_mihomo, validate_proxy_fields

SUBSCRIPTION_GENERATOR = "Clash-Config-Gen"
SUBSCRIPTION_PROJECT = "一万AI分享 Clash/OpenClash 订阅生成器"
SUBSCRIPTION_USAGE = "可直接导入 OpenClash、Clash Verge、FlClash 或 mihomo 兼容客户端"
SUBSCRIPTION_GITHUB_URL = "https://github.com/10000ge10000/clash-config-gen"
SUBSCRIPTION_PROJECT_URL = "https://clash.910501.xyz"
SUBSCRIPTION_ANNOUNCE = "\n".join(
    [
        f"Generator: {SUBSCRIPTION_GENERATOR}",
        f"Project: {SUBSCRIPTION_PROJECT}",
        f"Usage: {SUBSCRIPTION_USAGE}",
    ]
)
DUSTINWIN_RULESET_BASE_URL = "https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset"
DUSTINWIN_RULESET_INTERVAL = 604800
DUSTINWIN_RULESET_PATH_PREFIX = "./ruleset/dustinwin"


def _base64_utf8(value: str) -> str:
    return "base64:" + base64.b64encode(value.encode("utf-8")).decode("ascii")

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
    "Netflix": ("Media/Netflix", "Global TV"),
    "Spotify": ("Media/Spotify", "Global TV"),
    "YouTube": ("Media/YouTube", "Global TV"),
    "Max": ("Media/Max", "Global TV"),
    "Bilibili": ("Media/Bilibili", "CN Mainland TV"),
    "IQ": ("Media/IQ", "CN Mainland TV"),
    "IQIYI": ("Media/IQIYI", "CN Mainland TV"),
    "Letv": ("Media/Letv", "CN Mainland TV"),
    "Netease Music": ("Media/Netease%20Music", "CN Mainland TV"),
    "Tencent Video": ("Media/Tencent%20Video", "CN Mainland TV"),
    "Youku": ("Media/Youku", "CN Mainland TV"),
    "WeTV": ("Media/WeTV", "Global TV"),
    "ABC": ("Media/ABC", "Global TV"),
    "Abema TV": ("Media/Abema%20TV", "Asian TV"),
    "Amazon": ("Media/Amazon", "Global TV"),
    "Apple Music": ("Media/Apple%20Music", "Apple"),
    "Apple News": ("Media/Apple%20News", "Apple"),
    "Apple TV": ("Media/Apple%20TV", "Apple TV"),
    "Bahamut": ("Media/Bahamut", "Asian TV"),
    "BBC iPlayer": ("Media/BBC%20iPlayer", "Global TV"),
    "DAZN": ("Media/DAZN", "Global TV"),
    "Discovery Plus": ("Media/Discovery%20Plus", "Global TV"),
    "Disney Plus": ("Media/Disney%20Plus", "Global TV"),
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

DUSTINWIN_PROVIDERS_MAP = {
    "private": {"file": "private.mrs", "behavior": "domain", "format": "mrs", "target": "DIRECT"},
    "ads": {"file": "ads.mrs", "behavior": "domain", "format": "mrs", "target": "AdBlock"},
    "applications": {"file": "applications.list", "behavior": "classical", "format": "text", "target": "DIRECT"},
    "microsoft-cn": {"file": "microsoft-cn.mrs", "behavior": "domain", "format": "mrs", "target": "Microsoft"},
    "apple-cn": {"file": "apple-cn.mrs", "behavior": "domain", "format": "mrs", "target": "Apple"},
    "google-cn": {"file": "google-cn.mrs", "behavior": "domain", "format": "mrs", "target": "Google FCM"},
    "games-cn": {"file": "games-cn.mrs", "behavior": "domain", "format": "mrs", "target": "Steam"},
    "games": {"file": "games.mrs", "behavior": "domain", "format": "mrs", "target": "Steam"},
    "netflix": {"file": "netflix.mrs", "behavior": "domain", "format": "mrs", "target": "Global TV"},
    "disney": {"file": "disney.mrs", "behavior": "domain", "format": "mrs", "target": "Global TV"},
    "max": {"file": "max.mrs", "behavior": "domain", "format": "mrs", "target": "Global TV"},
    "primevideo": {"file": "primevideo.mrs", "behavior": "domain", "format": "mrs", "target": "Global TV"},
    "appletv": {"file": "appletv.mrs", "behavior": "domain", "format": "mrs", "target": "Apple TV"},
    "youtube": {"file": "youtube.mrs", "behavior": "domain", "format": "mrs", "target": "Global TV"},
    "tiktok": {"file": "tiktok.mrs", "behavior": "domain", "format": "mrs", "target": "TikTok"},
    "bilibili": {"file": "bilibili.mrs", "behavior": "domain", "format": "mrs", "target": "Domestic"},
    "spotify": {"file": "spotify.mrs", "behavior": "domain", "format": "mrs", "target": "Global TV"},
    "media": {"file": "media.mrs", "behavior": "domain", "format": "mrs", "target": "Global TV"},
    "ai": {"file": "ai.mrs", "behavior": "domain", "format": "mrs", "target": "AI Suite"},
    "networktest": {"file": "networktest.mrs", "behavior": "domain", "format": "mrs", "target": "Speedtest"},
    "tld-proxy": {"file": "tld-proxy.mrs", "behavior": "domain", "format": "mrs", "target": "Proxy"},
    "gfw": {"file": "gfw.mrs", "behavior": "domain", "format": "mrs", "target": "Proxy"},
    "proxy": {"file": "proxy.mrs", "behavior": "domain", "format": "mrs", "target": "Proxy"},
    "cn": {"file": "cn.mrs", "behavior": "domain", "format": "mrs", "target": "Domestic"},
    "privateip": {"file": "privateip.mrs", "behavior": "ipcidr", "format": "mrs", "target": "DIRECT", "no_resolve": True},
    "cnip": {"file": "cnip.mrs", "behavior": "ipcidr", "format": "mrs", "target": "Domestic", "no_resolve": True},
    "telegramip": {"file": "telegramip.mrs", "behavior": "ipcidr", "format": "mrs", "target": "Telegram", "no_resolve": True},
    "netflixip": {"file": "netflixip.mrs", "behavior": "ipcidr", "format": "mrs", "target": "Global TV", "no_resolve": True},
    "mediaip": {"file": "mediaip.mrs", "behavior": "ipcidr", "format": "mrs", "target": "Global TV", "no_resolve": True},
}


def text_to_list(text: str) -> list[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def first_non_empty_list(*values: str, fallback: str = "") -> list[str]:
    for value in values:
        items = text_to_list(value)
        if items:
            return items
    return text_to_list(fallback)


def int_config(value: Any, default: int, minimum: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= minimum else default


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def get_dustinwin_provider_url(file_name: str) -> str:
    if _bool_env("RULESET_CACHE_ENABLED", True):
        public_base_url = os.getenv("PUBLIC_BASE_URL", "https://clash.910501.xyz").rstrip("/")
        return f"{public_base_url}/ruleset/dustinwin/{file_name}"
    return f"{DUSTINWIN_RULESET_BASE_URL}/{file_name}"


def get_ruleset_update_interval() -> int:
    return int_config(os.getenv("RULESET_UPDATE_INTERVAL"), DUSTINWIN_RULESET_INTERVAL)


def build_config(
    proxies: list[dict[str, Any]],
    global_config: dict[str, Any],
    custom_rules: list[str] | None = None,
    custom_rule_providers: dict[str, Any] | None = None,
    selected_rule_type: str = "自定义规则",
) -> dict[str, Any]:
    """生成最终 Clash/OpenClash 配置；API 和 Web UI 都应复用这套逻辑。"""
    proxies = normalize_proxies_for_mihomo(proxies)
    global_config = apply_generation_profile(global_config)
    custom_rules = custom_rules or []
    custom_rule_providers = custom_rule_providers or {}
    generation_profile = global_config.get("generation_profile", "openclash-router")
    url_test_url = str(global_config.get("url_test_url") or DEFAULT_URL_TEST_URL).strip() or DEFAULT_URL_TEST_URL
    url_test_interval = int_config(global_config.get("url_test_interval"), DEFAULT_URL_TEST_INTERVAL)
    url_test_tolerance = int_config(global_config.get("url_test_tolerance"), DEFAULT_URL_TEST_TOLERANCE, minimum=0)
    if generation_profile == "minimal":
        final_proxy_groups = generate_minimal_proxy_groups(
            proxies,
            url_test_url=url_test_url,
            url_test_interval=url_test_interval,
            url_test_tolerance=url_test_tolerance,
        )
    else:
        final_proxy_groups = generate_proxy_groups(
            proxies,
            url_test_url=url_test_url,
            url_test_interval=url_test_interval,
            url_test_tolerance=url_test_tolerance,
        )

    final_config: dict[str, Any] = {
        "proxies": proxies,
        "proxy-groups": final_proxy_groups,
    }

    base_options = {
        "port": global_config.get("port", 7890),
        "socks-port": global_config.get("socks_port", 7891),
        "mixed-port": global_config.get("mixed_port", 7893),
        "allow-lan": global_config.get("allow_lan", False),
        "bind-address": global_config.get("bind_address", "*"),
        "mode": global_config.get("mode", "rule"),
        "log-level": global_config.get("log_level", "info"),
        "ipv6": global_config.get("ipv6_support", False),
        "find-process-mode": global_config.get("find_process_mode", "strict"),
    }
    if global_config.get("include_global_compat", False):
        final_config["global"] = dict(base_options)
    if global_config.get("include_inbound_ports", False):
        final_config.update(base_options)

    if global_config.get("include_controller", False):
        if global_config.get("external_controller"):
            final_config["external-controller"] = global_config["external_controller"]
        if global_config.get("secret"):
            final_config["secret"] = global_config["secret"]
        if global_config.get("external_ui"):
            final_config["external-ui"] = global_config["external_ui"]
        if global_config.get("external_ui_name"):
            final_config["external-ui-name"] = global_config["external_ui_name"]
        if global_config.get("external_ui_url"):
            final_config["external-ui-url"] = global_config["external_ui_url"]

    if global_config.get("include_router_options", False):
        for key, default in {
            "redir-port": global_config.get("redir_port"),
            "tproxy-port": global_config.get("tproxy_port"),
            "interface-name": global_config.get("interface_name"),
            "keep-alive-interval": global_config.get("keep_alive_interval"),
            "keep-alive-idle": global_config.get("keep_alive_idle"),
        }.items():
            if default not in (None, ""):
                final_config[key] = default

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

    if global_config.get("enable_dns", False):
        is_desktop = global_config.get("is_desktop", True)
        final_config["dns"] = {
            "enable": True,
            "fake-ip-filter": SOFT_ROUTER_FAKE_IP_FILTER_LIST if global_config.get("openclash_preset", False) else FAKE_IP_FILTER_LIST,
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
            dns_respect_rules = global_config.get("dns_respect_rules", False)
            final_config["dns"]["respect-rules"] = dns_respect_rules
            if global_config.get("fake_ip_filter_mode"):
                final_config["dns"]["fake-ip-filter-mode"] = global_config["fake_ip_filter_mode"]
            direct_nameserver = text_to_list(global_config.get("direct_nameserver", ""))
            if direct_nameserver:
                final_config["dns"]["direct-nameserver"] = direct_nameserver
            if dns_respect_rules:
                final_config["dns"]["proxy-server-nameserver"] = first_non_empty_list(
                    global_config.get("proxy_server_nameserver", ""),
                    global_config.get("direct_nameserver", ""),
                    global_config.get("default_nameserver", ""),
                    global_config.get("nameserver", ""),
                    fallback="223.5.5.5",
                )
            fallback = text_to_list(global_config.get("fallback", ""))
            if fallback:
                final_config["dns"]["fallback"] = fallback
                final_config["dns"]["fallback-filter"] = {"geoip": True, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"]}
            policy = _parse_nameserver_policy(global_config.get("nameserver_policy", ""))
            if policy:
                final_config["dns"]["nameserver-policy"] = policy
        else:
            # OpenClash 模式下仅保留必要的 DNS 字段
            dns_respect_rules = global_config.get("dns_respect_rules", False)
            final_config["dns"]["respect-rules"] = dns_respect_rules
            if dns_respect_rules:
                final_config["dns"]["proxy-server-nameserver"] = first_non_empty_list(
                    global_config.get("proxy_server_nameserver", ""),
                    global_config.get("direct_nameserver", ""),
                    global_config.get("default_nameserver", ""),
                    global_config.get("nameserver", ""),
                    fallback="223.5.5.5",
                )

    if global_config.get("enable_core_options", False):
        final_config["tcp-concurrent"] = global_config.get("tcp_concurrent", False)
        final_config["unified-delay"] = global_config.get("unified_delay", False)
        final_config["geodata-mode"] = global_config.get("geodata_mode", False)
        final_config["geodata-loader"] = global_config.get("geodata_loader", "standard")

    if global_config.get("enable_sniffer", False):
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

    if global_config.get("profile_store_selected", False) or global_config.get("profile_store_fake_ip", False):
        final_config["profile"] = {
            "store-selected": global_config.get("profile_store_selected", False),
            "store-fake-ip": global_config.get("profile_store_fake_ip", False),
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

    if generation_profile == "minimal":
        rules, rule_providers = ["MATCH,Proxy"], {}
    else:
        rules, rule_providers = build_rules(
            selected_rule_type,
            custom_rules,
            custom_rule_providers,
            global_config.get("lhie1_provider_targets", {}),
            global_config.get("dustinwin_provider_targets", {}),
        )
    if rule_providers:
        final_config["rule-providers"] = rule_providers
    final_config["rules"] = rules
    return final_config


def apply_generation_profile(global_config: dict[str, Any]) -> dict[str, Any]:
    config = dict(global_config or {})
    if "is_desktop" in config:
        profile = "desktop-full" if config.get("is_desktop", True) else "openclash-router"
    else:
        profile = config.get("generation_profile") or "desktop-full"
    config["generation_profile"] = profile
    if profile == "openclash-router":
        config.update({
            "include_global_compat": False,
            "include_inbound_ports": False,
            "include_controller": False,
            "include_router_options": False,
            "enable_core_options": False,
            "enable_dns": False,
            "enable_tun": False,
            "enable_sniffer": False,
            "profile_store_selected": False,
            "profile_store_fake_ip": False,
            "ntp_enable": False,
            "authentication": "",
        })
    if profile == "minimal":
        config.update({
            "include_global_compat": False,
            "include_inbound_ports": False,
            "include_controller": False,
            "include_router_options": False,
            "enable_core_options": False,
            "enable_dns": False,
            "enable_tun": False,
            "enable_sniffer": False,
            "ntp_enable": False,
            "profile_store_selected": False,
            "profile_store_fake_ip": False,
        })
    return config


def generate_minimal_proxy_groups(
    proxies: list[dict[str, Any]],
    url_test_url: str = DEFAULT_URL_TEST_URL,
    url_test_interval: int = DEFAULT_URL_TEST_INTERVAL,
    url_test_tolerance: int = DEFAULT_URL_TEST_TOLERANCE,
) -> list[dict[str, Any]]:
    node_names = [proxy["name"] for proxy in proxies if isinstance(proxy, dict) and proxy.get("name")]
    return [
        {
            "name": "Auto - UrlTest",
            "type": "url-test",
            "proxies": node_names,
            "url": url_test_url,
            "interval": url_test_interval,
            "tolerance": url_test_tolerance,
        },
        {"name": "Proxy", "type": "select", "proxies": ["Auto - UrlTest", "DIRECT"] + node_names},
    ]


def build_yaml(config: dict[str, Any]) -> str:
    header = "\n".join(
        [
            f"# Generator: {SUBSCRIPTION_GENERATOR}",
            f"# Generator-URL: {SUBSCRIPTION_GITHUB_URL}",
            f"# Project: {SUBSCRIPTION_PROJECT}",
            f"# Project-URL: {SUBSCRIPTION_PROJECT_URL}",
            f"# Usage: {SUBSCRIPTION_USAGE}",
            "# Note: 以 # 开头的内容是 YAML 注释，mihomo/OpenClash 会忽略",
            "",
        ]
    )
    return header + yaml.dump(
        config,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )


def build_subscription_headers(proxy_count: int, group_count: int) -> dict[str, str]:
    """构造 Clash/OpenClash 订阅元信息响应头。

    Subscription-Userinfo 只能表达流量/到期信息，OpenClash 会固定渲染成
    流量条。这里不返回它，避免用户误以为存在流量限制。Profile-Title、
    Profile-Web-Page-Url、Support-Url 和 Announce 是 Clash 系订阅常见
    元信息字段；中文正文用 base64 UTF-8 包装，避免 HTTP 响应头编码问题。
    """
    return {
        "Profile-Update-Interval": "24",
        "Profile-Title": SUBSCRIPTION_GENERATOR,
        "Profile-Web-Page-Url": SUBSCRIPTION_GITHUB_URL,
        "Support-Url": SUBSCRIPTION_PROJECT_URL,
        "Announce": _base64_utf8(SUBSCRIPTION_ANNOUNCE),
        "X-Clash-Config-Project-Url": SUBSCRIPTION_PROJECT_URL,
        "Content-Disposition": 'inline; filename="clash-config.yaml"',
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Clash-Proxy-Count": str(proxy_count),
        "X-Clash-Proxy-Group-Count": str(group_count),
    }


def validate_config(config: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    proxies = config.get("proxies") or []
    groups = config.get("proxy-groups") or []
    rules = config.get("rules") or []

    if not proxies:
        errors.append("Proxies 为空")
    if not groups:
        errors.append("Proxy Groups 为空")
    if not any(str(rule).startswith("MATCH,") for rule in rules):
        errors.append("Rules 缺少 MATCH 兜底规则")

    proxy_names = [p.get("name") for p in proxies if isinstance(p, dict)]
    group_names = [g.get("name") for g in groups if isinstance(g, dict)]
    valid_targets = set(proxy_names + group_names + ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "no-resolve"])

    for proxy in proxies:
        if not isinstance(proxy, dict):
            errors.append("存在非字典格式的节点")
            continue
        for proxy_error in validate_proxy_fields(proxy):
            errors.append(f"节点 '{proxy.get('name', '未命名节点')}' {proxy_error}")

    for group in groups:
        for target in group.get("proxies", []):
            if target not in valid_targets:
                warnings.append(f"策略组 '{group.get('name')}' 引用了不存在的节点/组: '{target}'")

    for rule in rules:
        parts = str(rule).split(",")
        if len(parts) >= 2:
            # Clash/Mihomo 规则允许在最后追加 no-resolve，例如：
            # GEOIP,CN,Domestic,no-resolve
            # 真正的策略组目标是倒数第二段。如果直接取最后一段，会漏掉
            # Domestic 这类缺失策略组，坏配置就会被误判为可用。
            target = parts[-2] if parts[-1] == "no-resolve" and len(parts) >= 3 else parts[-1]
            if target not in valid_targets and target != "no-resolve":
                warnings.append(f"规则 '{rule}' 指向了不存在的策略组: '{target}'")

    dns_config = config.get("dns") or {}
    if dns_config.get("respect-rules") and not dns_config.get("proxy-server-nameserver"):
        errors.append("dns.respect-rules 已启用，但 dns.proxy-server-nameserver 为空")

    try:
        yaml.safe_load(build_yaml(config))
    except Exception as exc:
        errors.append(f"YAML 反解析失败: {exc}")

    return errors, warnings


def build_rules(
    selected_rule_type: str,
    custom_rules: list[str],
    custom_rule_providers: dict[str, Any],
    lhie1_provider_targets: dict[str, str] | None = None,
    dustinwin_provider_targets: dict[str, str] | None = None,
) -> tuple[list[str], dict[str, Any]]:
    rule_providers: dict[str, Any] = {}
    lhie1_provider_targets = lhie1_provider_targets or {}
    dustinwin_provider_targets = dustinwin_provider_targets or {}
    if selected_rule_type == "dustinwin规则":
        rule_list = [
            "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
            "DOMAIN-SUFFIX,services.googleapis.cn,Proxy",
        ]
        interval = get_ruleset_update_interval()
        for name, provider_config in DUSTINWIN_PROVIDERS_MAP.items():
            file_name = str(provider_config["file"])
            target = dustinwin_provider_targets.get(name) or str(provider_config["target"])
            rule_providers[name] = {
                "type": "http",
                "behavior": provider_config["behavior"],
                "format": provider_config["format"],
                "url": get_dustinwin_provider_url(file_name),
                "path": f"{DUSTINWIN_RULESET_PATH_PREFIX}/{file_name}",
                "interval": interval,
            }
            suffix = ",no-resolve" if provider_config.get("no_resolve") else ""
            rule_list.append(f"RULE-SET,{name},{target}{suffix}")
        rule_list.append("MATCH,Others")
    elif selected_rule_type == "lhie1规则":
        base_url = "https://testingcf.jsdelivr.net/gh/dler-io/Rules@main/Clash/Provider"
        rule_list = [
            "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
            "DOMAIN-SUFFIX,services.googleapis.cn,Proxy",
        ]
        for name, (suffix, target) in LHIE1_PROVIDERS_MAP.items():
            target = lhie1_provider_targets.get(name) or target
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
