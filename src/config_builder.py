import base64
import os
import re
from typing import Any
from urllib.parse import quote

import yaml

from clash_meta_gen import (
    DEFAULT_URL_TEST_INTERVAL,
    DEFAULT_URL_TEST_TOLERANCE,
    DEFAULT_URL_TEST_URL,
    generate_proxy_groups,
)
from normalizer import (
    normalize_proxies_for_mihomo,
    strip_internal_proxy_metadata,
    validate_proxy_fields,
)

SUBSCRIPTION_GENERATOR = "Clash-Config-Gen"
SUBSCRIPTION_PROJECT = "一万AI分享 Clash/OpenClash 订阅生成器"
SUBSCRIPTION_USAGE = "可直接导入 OpenClash、Nikki、Clash Verge Rev、FlClash 或其他 mihomo 兼容客户端"
SUBSCRIPTION_GITHUB_URL = "https://github.com/10000ge10000/clash-config-gen"
SUBSCRIPTION_PROJECT_URL = SUBSCRIPTION_GITHUB_URL  # 客户端展示的项目主页：使用开源仓库地址
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
GOOGLE_RULESET_FILE = "google.list"
GOOGLE_RULESET_URL = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.list"
DEFAULT_RULE_TYPE = "dustinwin规则"


# 已改名的策略组：旧草稿、自定义规则和目标覆盖里的旧名在生成时自动换成新名。
LEGACY_GROUP_RENAMES = {"Steam": "Game"}
# mihomo 规则末尾可选的修饰参数，不是策略组目标。
RULE_TRAILING_PARAMS = {"no-resolve", "src"}
RULESET_PREPEND_ORDERS = {"优先 (覆盖)", "prepend"}


def rename_legacy_target(target: Any) -> Any:
    if isinstance(target, str):
        return LEGACY_GROUP_RENAMES.get(target.strip(), target)
    return target


def rule_target_index(parts: list[str]) -> int:
    """规则的策略组目标所在下标：跳过末尾的 no-resolve / src 修饰参数。"""
    index = len(parts) - 1
    while index >= 2 and parts[index].strip() in RULE_TRAILING_PARAMS:
        index -= 1
    return index


def rename_legacy_rule_target(rule: Any) -> Any:
    if not isinstance(rule, str) or "," not in rule:
        return rule
    parts = rule.split(",")
    index = rule_target_index(parts)
    renamed = LEGACY_GROUP_RENAMES.get(parts[index].strip())
    if not renamed:
        return rule
    parts[index] = renamed
    return ",".join(parts)


def builtin_ruleset_names() -> set[str]:
    """内置规则集占用的名称，自定义规则集不能重名，否则会顶掉内置定义。"""
    return set(DUSTINWIN_PROVIDERS_MAP)


def is_no_base_rule_type(value: object) -> bool:
    """Return whether the draft explicitly requests only user rules/providers.

    ``自定义规则`` was the label used by the first V2 drafts.  Keep it as an
    input alias while exposing the clearer ``none`` value to new clients.
    """
    normalized = str(value or "").strip().lower()
    return normalized in {"none", "无基础规则", "自定义规则", "custom"}


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

META_RULESET_BASE_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite"


def _meta_provider(upstream_name: str, local_name: str, target: str) -> dict[str, Any]:
    """MetaCubeX/meta-rules-dat 的 geosite mrs：补齐 DustinWin 没有的专项服务。

    本地文件名与上游分开，避免 category-scholar-!cn 这类名字里的特殊字符进入缓存路径和 URL。
    """
    return {
        "file": f"{local_name}.mrs",
        "behavior": "domain",
        "format": "mrs",
        "target": target,
        "url": f"{META_RULESET_BASE_URL}/{quote(upstream_name, safe='')}.mrs",
        "source": "MetaCubeX/meta-rules-dat",
    }


# 唯一的内置规则源：DustinWin 为主，MetaCubeX meta-rules-dat 补齐专项服务。
# 字典顺序就是生成顺序，要点：
# - ai、youtube 在 ads 前，避免 AI 服务依赖的统计域名被拦；
# - 国内可直连集合（*-cn、googlefcm）在完整 Google 列表前，完整列表会吞掉它们；
# - 专项服务集合在 media、gfw、proxy、cn 这些大名单之前，否则永远命中不到；
# - IP 集合放最后，cnip 兜底。
DUSTINWIN_PROVIDERS_MAP = {
    "private": {"file": "private.mrs", "behavior": "domain", "format": "mrs", "target": "DIRECT"},
    "ai": {"file": "ai.mrs", "behavior": "domain", "format": "mrs", "target": "AI Suite"},
    "youtube": {"file": "youtube.mrs", "behavior": "domain", "format": "mrs", "target": "Youtube"},
    "ads": {"file": "ads.mrs", "behavior": "domain", "format": "mrs", "target": "AdBlock"},
    "applications": {"file": "applications.list", "behavior": "classical", "format": "text", "target": "DIRECT"},
    "microsoft-cn": {"file": "microsoft-cn.mrs", "behavior": "domain", "format": "mrs", "target": "Microsoft"},
    "apple-cn": {"file": "apple-cn.mrs", "behavior": "domain", "format": "mrs", "target": "Apple"},
    "googlefcm": _meta_provider("googlefcm", "googlefcm", "Google FCM"),
    # google-cn / games-cn 是国内可直连的域名：Google、Game 组还承接境外流量，默认走代理，不能共用。
    "google-cn": {"file": "google-cn.mrs", "behavior": "domain", "format": "mrs", "target": "Domestic"},
    "games-cn": {"file": "games-cn.mrs", "behavior": "domain", "format": "mrs", "target": "Domestic"},
    # 学术集合包含 scholar.google.*，必须在完整 Google 列表之前，否则谷歌学术不受 Scholar 组控制。
    "scholar": _meta_provider("category-scholar-!cn", "scholar", "Scholar"),
    "google": {"file": GOOGLE_RULESET_FILE, "behavior": "classical", "format": "text", "target": "Google", "url": GOOGLE_RULESET_URL},
    "telegram": _meta_provider("telegram", "telegram", "Telegram"),
    "discord": _meta_provider("discord", "discord", "Discord"),
    "paypal": _meta_provider("paypal", "paypal", "PayPal"),
    "crypto": _meta_provider("category-cryptocurrency", "crypto", "Crypto"),
    "mihoyo": _meta_provider("mihoyo", "mihoyo", "miHoYo"),
    "games": {"file": "games.mrs", "behavior": "domain", "format": "mrs", "target": "Game"},
    "netflix": {"file": "netflix.mrs", "behavior": "domain", "format": "mrs", "target": "Netflix"},
    "disney": {"file": "disney.mrs", "behavior": "domain", "format": "mrs", "target": "Disney Plus"},
    "max": {"file": "max.mrs", "behavior": "domain", "format": "mrs", "target": "HBO Max"},
    "primevideo": {"file": "primevideo.mrs", "behavior": "domain", "format": "mrs", "target": "Global TV"},
    "appletv": {"file": "appletv.mrs", "behavior": "domain", "format": "mrs", "target": "Apple TV"},
    "abema": _meta_provider("abema", "abema", "Asian TV"),
    "bahamut": _meta_provider("bahamut", "bahamut", "Bahamut"),
    "dazn": _meta_provider("dazn", "dazn", "DAZN"),
    "discoveryplus": _meta_provider("discoveryplus", "discoveryplus", "Discovery Plus"),
    "pornhub": _meta_provider("pornhub", "pornhub", "Pornhub"),
    "tiktok": {"file": "tiktok.mrs", "behavior": "domain", "format": "mrs", "target": "TikTok"},
    "bilibili": {"file": "bilibili.mrs", "behavior": "domain", "format": "mrs", "target": "Bilibili"},
    "spotify": {"file": "spotify.mrs", "behavior": "domain", "format": "mrs", "target": "Spotify"},
    "media": {"file": "media.mrs", "behavior": "domain", "format": "mrs", "target": "Global TV"},
    "networktest": {"file": "networktest.mrs", "behavior": "domain", "format": "mrs", "target": "Speedtest"},
    "tld-proxy": {"file": "tld-proxy.mrs", "behavior": "domain", "format": "mrs", "target": "Proxy"},
    "gfw": {"file": "gfw.mrs", "behavior": "domain", "format": "mrs", "target": "Proxy"},
    "proxy": {"file": "proxy.mrs", "behavior": "domain", "format": "mrs", "target": "Proxy"},
    "cn": {"file": "cn.mrs", "behavior": "domain", "format": "mrs", "target": "Domestic"},
    "privateip": {"file": "privateip.mrs", "behavior": "ipcidr", "format": "mrs", "target": "DIRECT", "no_resolve": True},
    "telegramip": {"file": "telegramip.mrs", "behavior": "ipcidr", "format": "mrs", "target": "Telegram", "no_resolve": True},
    "netflixip": {"file": "netflixip.mrs", "behavior": "ipcidr", "format": "mrs", "target": "Netflix", "no_resolve": True},
    "mediaip": {"file": "mediaip.mrs", "behavior": "ipcidr", "format": "mrs", "target": "Global TV", "no_resolve": True},
    "cnip": {"file": "cnip.mrs", "behavior": "ipcidr", "format": "mrs", "target": "Domestic", "no_resolve": True},
}


# 规则集的中文说明，只用于界面展示。
DUSTINWIN_RULE_LABELS = {
    "private": "私有网络域名", "ads": "广告域名", "applications": "下载类应用", "microsoft-cn": "微软国内域名",
    "apple-cn": "苹果国内域名", "google": "Google 服务", "google-cn": "Google 国内域名", "games-cn": "游戏国内域名",
    "games": "游戏平台", "netflix": "Netflix", "disney": "Disney+", "max": "HBO Max", "primevideo": "Prime Video",
    "appletv": "Apple TV", "youtube": "YouTube", "tiktok": "TikTok", "bilibili": "哔哩哔哩", "spotify": "Spotify",
    "media": "其他流媒体", "ai": "AI 服务", "networktest": "测速站点", "tld-proxy": "境外顶级域名",
    "gfw": "GFW 名单", "proxy": "代理域名", "cn": "国内域名", "privateip": "私有网络 IP", "cnip": "国内 IP",
    "telegramip": "Telegram IP", "netflixip": "Netflix IP", "mediaip": "流媒体 IP",
    "googlefcm": "Google 推送", "telegram": "Telegram", "discord": "Discord", "paypal": "PayPal",
    "crypto": "加密货币", "scholar": "学术站点", "mihoyo": "米哈游", "abema": "AbemaTV",
    "bahamut": "巴哈姆特动画疯", "dazn": "DAZN", "discoveryplus": "Discovery+", "pornhub": "Pornhub",
}
# 已下线的 lhie1 规则源：旧草稿里的取值按内置规则源处理。
LEGACY_RULE_TYPES = {"lhie1规则": DEFAULT_RULE_TYPE}


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


def get_public_base_url() -> str:
    """统一读取对外地址；未设置时返回空串，调用方需自行处理。"""
    return os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")


def get_dustinwin_provider_url(file_name: str, source_url: str | None = None) -> str:
    public_base_url = get_public_base_url()
    # 未配置公网地址时无法生成本站缓存链接，回退为上游直链而不是生成相对地址。
    if public_base_url and _bool_env("RULESET_CACHE_ENABLED", True):
        return f"{public_base_url}/ruleset/dustinwin/{file_name}"
    return source_url or f"{DUSTINWIN_RULESET_BASE_URL}/{file_name}"


def get_ruleset_update_interval() -> int:
    return int_config(os.getenv("RULESET_UPDATE_INTERVAL"), DUSTINWIN_RULESET_INTERVAL)


def build_config(
    proxies: list[dict[str, Any]],
    global_config: dict[str, Any],
    custom_rules: list[str] | None = None,
    custom_rule_providers: dict[str, Any] | None = None,
    selected_rule_type: str = DEFAULT_RULE_TYPE,
) -> dict[str, Any]:
    """生成最终 Clash/OpenClash 配置；API 和 Web UI 都应复用这套逻辑。"""
    proxies = [
        strip_internal_proxy_metadata(proxy)
        for proxy in normalize_proxies_for_mihomo(proxies)
    ]
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

    if generation_profile == "minimal" and not is_no_base_rule_type(selected_rule_type):
        rules, rule_providers = ["MATCH,Proxy"], {}
    elif generation_profile == "minimal":
        rules, rule_providers = build_rules(
            selected_rule_type,
            custom_rules,
            custom_rule_providers,
            global_config.get("dustinwin_provider_targets", {}),
        )
    else:
        rules, rule_providers = build_rules(
            selected_rule_type,
            custom_rules,
            custom_rule_providers,
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


def _subscription_profile_name_headers(profile_name: str | None) -> dict[str, str]:
    """按配置名称生成 Profile-Title 与 Content-Disposition。

    Hiddify 读 Profile-Title，FlClash 读 Content-Disposition 的文件名且不去扩展名，
    所以文件名不带 .yaml。名称来自用户名，非白名单字符一律走编码形式，防止响应头注入。
    """
    name = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", profile_name or "").strip()[:64]
    if not name:
        return {
            "Profile-Title": SUBSCRIPTION_GENERATOR,
            "Content-Disposition": 'inline; filename="clash-config.yaml"',
        }
    if re.fullmatch(r"[A-Za-z0-9._-]+", name):
        return {
            "Profile-Title": name,
            "Content-Disposition": f'inline; filename="{name}"',
        }
    return {
        "Profile-Title": _base64_utf8(name),
        "Content-Disposition": f"""inline; filename="clash-config"; filename*=UTF-8''{quote(name, safe='')}""",
    }


def build_subscription_headers(
    proxy_count: int,
    group_count: int,
    profile_name: str | None = None,
) -> dict[str, str]:
    """构造 Clash/OpenClash 订阅元信息响应头。

    Subscription-Userinfo 只能表达流量/到期信息，OpenClash 会固定渲染成
    流量条。这里不返回它，避免用户误以为存在流量限制。Profile-Title、
    Profile-Web-Page-Url、Support-Url 和 Announce 是 Clash 系订阅常见
    元信息字段；中文正文用 base64 UTF-8 包装，避免 HTTP 响应头编码问题。
    """
    return {
        "Profile-Update-Interval": "24",
        **_subscription_profile_name_headers(profile_name),
        "Profile-Web-Page-Url": SUBSCRIPTION_GITHUB_URL,
        "Support-Url": SUBSCRIPTION_PROJECT_URL,
        "Announce": _base64_utf8(SUBSCRIPTION_ANNOUNCE),
        "X-Clash-Config-Project-Url": SUBSCRIPTION_PROJECT_URL,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Clash-Proxy-Count": str(proxy_count),
        "X-Clash-Proxy-Group-Count": str(group_count),
    }


def validate_config(
    config: dict[str, Any],
    *,
    allow_no_match: bool = False,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    proxies = config.get("proxies") or []
    groups = config.get("proxy-groups") or []
    rules = config.get("rules") or []

    if not proxies:
        errors.append("Proxies 为空")
    if not groups:
        errors.append("Proxy Groups 为空")
    if not allow_no_match and not any(_is_match_rule(rule) for rule in rules):
        errors.append("Rules 缺少 MATCH 兜底规则")

    proxy_names = [p.get("name") for p in proxies if isinstance(p, dict)]
    group_names = [g.get("name") for g in groups if isinstance(g, dict)]
    # no-resolve 是规则末尾的修饰符，不是可跳转的策略组目标。
    valid_targets = set(proxy_names + group_names + ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"])
    provider_names = set((config.get("rule-providers") or {}).keys())
    sub_rule_names = set((config.get("sub-rules") or {}).keys())

    for proxy in proxies:
        if not isinstance(proxy, dict):
            errors.append("存在非字典格式的节点")
            continue
        for proxy_error in validate_proxy_fields(proxy):
            errors.append(f"节点 '{proxy.get('name', '未命名节点')}' {proxy_error}")

    for group in groups:
        for target in group.get("proxies", []):
            if target not in valid_targets:
                errors.append(f"策略组 '{group.get('name')}' 引用了不存在的节点/组: '{target}'")

    for rule in rules:
        parts = str(rule).split(",")
        if len(parts) >= 2:
            # 规则末尾可以带 no-resolve / src 修饰参数，例如 GEOIP,CN,Domestic,no-resolve；
            # 真正的目标在修饰参数之前。直接取最后一段会把缺失的策略组误判为可用。
            rule_type = parts[0].strip().upper()
            target = parts[rule_target_index(parts)].strip()
            if rule_type == "SUB-RULE":
                if target not in sub_rule_names:
                    errors.append(f"规则 '{rule}' 引用了不存在的子规则: '{target}'")
                continue
            if target not in valid_targets:
                errors.append(f"规则 '{rule}' 指向了不存在的策略组: '{target}'")
            if rule_type == "RULE-SET" and len(parts) >= 3 and parts[1].strip() not in provider_names:
                errors.append(f"规则 '{rule}' 引用了不存在的规则集: '{parts[1].strip()}'")

    dns_config = config.get("dns") or {}
    if dns_config.get("respect-rules") and not dns_config.get("proxy-server-nameserver"):
        errors.append("dns.respect-rules 已启用，但 dns.proxy-server-nameserver 为空")

    try:
        yaml.safe_load(build_yaml(config))
    except Exception as exc:
        errors.append(f"YAML 反解析失败: {exc}")

    return errors, warnings


def _is_match_rule(rule: object) -> bool:
    return str(rule).split(",", 1)[0].strip().upper() == "MATCH"


def build_rules(
    selected_rule_type: str,
    custom_rules: list[str],
    custom_rule_providers: dict[str, Any],
    dustinwin_provider_targets: dict[str, str] | None = None,
) -> tuple[list[str], dict[str, Any]]:
    rule_providers: dict[str, Any] = {}
    selected_rule_type = LEGACY_RULE_TYPES.get(selected_rule_type, selected_rule_type)
    dustinwin_provider_targets = {
        name: rename_legacy_target(target) for name, target in (dustinwin_provider_targets or {}).items()
    }
    custom_rules = [rename_legacy_rule_target(rule) for rule in custom_rules]
    if selected_rule_type == "dustinwin规则":
        rule_list = [
            "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
            "DOMAIN-SUFFIX,services.googleapis.cn,Google",
        ]
        interval = get_ruleset_update_interval()
        # 生成顺序即 DUSTINWIN_PROVIDERS_MAP 的定义顺序，排序依据见该字典上方的注释。
        for name, provider_config in DUSTINWIN_PROVIDERS_MAP.items():
            file_name = str(provider_config["file"])
            target = dustinwin_provider_targets.get(name) or str(provider_config["target"])
            rule_providers[name] = {
                "type": "http",
                "behavior": provider_config["behavior"],
                "format": provider_config["format"],
                "url": get_dustinwin_provider_url(file_name, provider_config.get("url")),
                "path": f"{DUSTINWIN_RULESET_PATH_PREFIX}/{file_name}",
                "interval": interval,
            }
            suffix = ",no-resolve" if provider_config.get("no_resolve") else ""
            rule_list.append(f"RULE-SET,{name},{target}{suffix}")
        rule_list.append("MATCH,Others")
    elif is_no_base_rule_type(selected_rule_type):
        # Explicit "none"/custom mode deliberately has no built-in rules and
        # no implicit MATCH fallback.  The caller owns the complete rule list.
        rule_list = []
    else:
        # Preserve the historical fallback for unknown legacy values while
        # making the supported no-base mode explicit above.
        rule_list = [
            "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
            "DOMAIN-SUFFIX,services.googleapis.cn,Google",
            "DOMAIN-SUFFIX,google.com,Google",
            "DOMAIN-SUFFIX,youtube.com,Youtube",
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
        if "proxy" in config:
            # Preserve the provider transport selector verbatim.  The API
            # canonicalizes private user versions to DIRECT; external HTTP
            # providers keep whatever explicit value the user supplied.
            provider["proxy"] = config["proxy"]
        if config.get("format"):
            provider["format"] = config["format"]
        rule_providers[name] = provider

        target = rename_legacy_target(config.get("target", "Proxy"))
        # ipcidr 规则集不加 no-resolve 时，排在它后面的所有域名请求都要先做一次 DNS 解析。
        suffix = ",no-resolve" if provider["behavior"] == "ipcidr" else ""
        if config.get("order") in RULESET_PREPEND_ORDERS:
            provider_rules_prepend.append(f"RULE-SET,{name},{target}{suffix}")
        else:
            provider_rules_append.append(f"RULE-SET,{name},{target}{suffix}")

    preset_normal = [rule for rule in rule_list if not _is_match_rule(rule)]
    preset_match = [rule for rule in rule_list if _is_match_rule(rule)]
    # MATCH 命中后不再继续匹配：自定义 MATCH 只能作为兜底放在最后（替换基础规则源的兜底），
    # 否则排在它后面的规则集和基础规则全部失效。多条时第一条生效，其余本就不可达。
    custom_normal = [rule for rule in custom_rules if not _is_match_rule(rule)]
    custom_match = [rule for rule in custom_rules if _is_match_rule(rule)]
    final_match = custom_match[:1] or preset_match
    final_rules = custom_normal + provider_rules_prepend + preset_normal + provider_rules_append + final_match
    if not is_no_base_rule_type(selected_rule_type) and not any(_is_match_rule(rule) for rule in final_rules):
        final_rules.append("MATCH,Proxy")
    return final_rules, rule_providers


def _catalog_entry(rule: str, overridable: set[str], labels: dict[str, str]) -> dict[str, Any]:
    parts = rule.split(",")
    no_resolve = parts[-1] == "no-resolve"
    if no_resolve:
        parts = parts[:-1]
    rule_type, value, target = parts[0], ",".join(parts[1:-1]), parts[-1]
    is_provider = rule_type == "RULE-SET"
    return {
        "type": rule_type,
        "value": value,
        "target": target,
        "no_resolve": no_resolve,
        "overridable": is_provider and value in overridable,
        "label": labels.get(value, "") if is_provider else "内置规则",
    }


def build_rule_catalog() -> dict[str, dict[str, Any]]:
    """各规则源的真实基础规则（按生成顺序），前端据此展示实际分流列表。

    直接取 build_rules 的输出而不是另写一份顺序，保证界面与生成结果一致。
    """
    sources = (
        ("dustinwin规则", "dustinwin", "DustinWin + MetaCubeX", set(DUSTINWIN_PROVIDERS_MAP), DUSTINWIN_RULE_LABELS),
    )
    catalog: dict[str, dict[str, Any]] = {}
    for rule_type, key, label, overridable, labels in sources:
        rules, _ = build_rules(rule_type, [], {})
        fallback = next((rule.split(",", 1)[1] for rule in rules if _is_match_rule(rule)), None)
        catalog[rule_type] = {
            "key": key,
            "label": label,
            "rules": [_catalog_entry(rule, overridable, labels) for rule in rules if not _is_match_rule(rule)],
            "fallback": fallback,
        }
    catalog["none"] = {"key": "", "label": "无基础规则", "rules": [], "fallback": None}
    return catalog


_POLICY_KEY_PREFIXES = ("geosite", "rule-set", "geoip")


def _split_policy_line(line: str) -> tuple[str, str] | None:
    """拆分 “域名或分类: DNS” 一行。

    键本身可能带冒号（geosite:cn、rule-set:xxx），值可能是 https://… 地址，
    所以优先按 “冒号+空格” 拆；没有空格时跳过 geosite: 这类前缀里的冒号。
    """
    if ": " in line:
        key, value = line.split(": ", 1)
        return key, value
    if ":" not in line:
        return None
    prefix, rest = line.split(":", 1)
    if prefix.strip().lower() in _POLICY_KEY_PREFIXES and ":" in rest:
        name, value = rest.split(":", 1)
        return f"{prefix}:{name}", value
    return prefix, rest


def _parse_nameserver_policy(raw_policy: str) -> dict[str, str]:
    policy: dict[str, str] = {}
    for line in (raw_policy or "").splitlines():
        parsed = _split_policy_line(line)
        if not parsed:
            continue
        key, value = parsed
        key = key.strip()
        value = value.strip()
        if key and value:
            policy[key] = value
    return policy
