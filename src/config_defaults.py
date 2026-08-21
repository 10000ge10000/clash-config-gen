def build_default_global_config() -> dict:
    """返回每个用户独立的 OpenClash 默认全局配置。"""
    return {
        # 基础
        "include_global_compat": False,
        "include_inbound_ports": False,
        "include_controller": False,
        "include_router_options": False,
        "enable_core_options": False,
        "optional_globals_v2": True,
        "port": 7890,
        "socks_port": 7891,
        "mixed_port": 7893,
        "allow_lan": False,
        "bind_address": "*",
        "mode": "rule",
        "log_level": "info",
        "ipv6_support": False,
        "external_controller": "0.0.0.0:9090",
        "secret": "",
        "redir_port": 7892,
        "tproxy_port": 7895,
        "interface_name": "",
        "external_ui": "",
        "external_ui_name": "",
        "external_ui_url": "",
        # 性能与网络
        "keep_alive_interval": 15,
        "keep_alive_idle": 600,
        "url_test_url": "http://cp.cloudflare.com/generate_204",
        "url_test_interval": 60,
        "url_test_tolerance": 30,
        "tcp_concurrent": False,
        "unified_delay": False,
        "find_process_mode": "strict",
        "geodata_mode": False,
        "geodata_loader": "standard",
        # TUN
        "enable_tun": False,
        "tun_stack": "mixed",
        "tun_device": "utun",
        "tun_auto_route": False,
        "tun_auto_detect_interface": False,
        "tun_dns_hijack": False,
        "tun_dns_hijack_value": "127.0.0.1:53",
        "tun_endpoint_independent_nat": False,
        "tun_auto_redirect": False,
        "tun_strict_route": False,
        # DNS
        "enable_dns": False,
        "dns_listen": "0.0.0.0:7874",
        "dns_ipv6": False,
        "enhanced_mode": "fake-ip",
        "fake_ip_range": "198.18.0.1/16",
        "fake_ip_range6": "fc00::/18",
        "fake_ip_filter_mode": "blacklist",
        "dns_respect_rules": False,
        "direct_nameserver": "",
        "proxy_server_nameserver": "",
        "default_nameserver": "223.5.5.5\n119.29.29.29",
        "nameserver": "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
        "fallback": "https://1.1.1.1/dns-query\ntcp://8.8.8.8",
        "nameserver_policy": "",
        # 嗅探
        "enable_sniffer": False,
        "sniff_override_dest": False,
        "sniffer_parse_pure_ip": False,
        "sniffer_force_dns_mapping": False,
        # OpenClash / 软路由
        "openclash_preset": False,
        "profile_store_selected": False,
        "profile_store_fake_ip": False,
        "ntp_enable": False,
        "ntp_server": "time.apple.com",
        "ntp_port": 123,
        "ntp_interval": 30,
        "ntp_write_to_system": False,
        "authentication": "",
        # 规则
        "generation_profile": "openclash-router",
        "is_desktop": False,
        "lhie1_provider_targets": {},
        "dustinwin_provider_targets": {},
    }


# 两个 DNS 防泄露预设的全局配置覆盖体，供 Streamlit 侧边栏与 V2 API 共用。
FULL_CLIENT_DNS_PRESET = {
    "include_global_compat": False,
    "include_inbound_ports": False,
    "include_controller": False,
    "include_router_options": False,
    "enable_core_options": True,
    "tcp_concurrent": True,
    "unified_delay": True,
    "geodata_mode": True,
    "enable_dns": True,
    "dns_listen": "0.0.0.0:7874",
    "dns_ipv6": False,
    "enhanced_mode": "fake-ip",
    "fake_ip_range": "198.18.0.1/16",
    "fake_ip_range6": "fc00::/18",
    "fake_ip_filter_mode": "blacklist",
    "default_nameserver": "223.5.5.5\n119.29.29.29",
    "nameserver": "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
    "direct_nameserver": "223.5.5.5\n119.29.29.29",
    "proxy_server_nameserver": "223.5.5.5",
    "fallback": "",
    "dns_respect_rules": True,
    "openclash_preset": False,
    "enable_tun": True,
    "tun_stack": "mixed",
    "tun_auto_route": True,
    "tun_auto_detect_interface": True,
    "tun_dns_hijack": True,
    "tun_dns_hijack_value": "127.0.0.1:53",
    "tun_endpoint_independent_nat": True,
    "tun_auto_redirect": False,
    "tun_strict_route": True,
    "enable_sniffer": True,
    "sniff_override_dest": True,
    "sniffer_parse_pure_ip": True,
    "sniffer_force_dns_mapping": True,
    "profile_store_selected": True,
    "profile_store_fake_ip": True,
    "generation_profile": "desktop-full",
    "is_desktop": True,
    "target_mode_user_selected": True,
}


OPENCLASH_ROUTER_SAFE_PRESET = {
    "include_global_compat": False,
    "include_inbound_ports": False,
    "include_controller": False,
    "include_router_options": False,
    "enable_core_options": False,
    "enable_dns": False,
    "dns_respect_rules": False,
    "direct_nameserver": "",
    "proxy_server_nameserver": "",
    "enable_tun": False,
    "tun_dns_hijack": False,
    "tun_strict_route": False,
    "enable_sniffer": False,
    "sniff_override_dest": False,
    "sniffer_parse_pure_ip": False,
    "sniffer_force_dns_mapping": False,
    "openclash_preset": False,
    "profile_store_selected": False,
    "profile_store_fake_ip": False,
    "generation_profile": "openclash-router",
    "is_desktop": False,
    "target_mode_user_selected": True,
}


def migrate_global_defaults(global_config: dict, saved_global_config: dict) -> dict:
    """把旧默认值迁移到当前推荐值，避免老账号继续显示旧 UI 默认。"""
    migrated = dict(global_config)
    if saved_global_config.get("url_test_tolerance") in (None, 50):
        migrated["url_test_tolerance"] = 30
    if (
        not saved_global_config.get("target_mode_user_selected")
        and "generation_profile" not in saved_global_config
        and "is_desktop" not in saved_global_config
    ):
        migrated["generation_profile"] = "openclash-router"
        migrated["is_desktop"] = False
    return migrated


def apply_v2_global_defaults(global_config: dict, saved_global_config: dict) -> dict:
    """Web 工作台与 V2 API 共用的默认合并：已保存值覆盖默认值，再迁移旧默认。

    注意：不要在这里对老账号强制重置可选开关——saved 中显式保存过的值必须保留，
    缺省的键自然继承 build_default_global_config 的默认值。
    """
    merged = dict(global_config)
    merged.update(saved_global_config or {})
    merged = migrate_global_defaults(merged, saved_global_config)
    merged["optional_globals_v2"] = True
    return merged


def _global_schema_field(
    key: str,
    label: str,
    field_type: str = "text",
    *,
    options: list | None = None,
    visible: dict | None = None,
    help_: str = "",
) -> dict:
    control_type = "input" if field_type in {"text", "password", "number"} else field_type
    field = {
        "key": key,
        "label": label,
        "type": control_type,
        "default": build_default_global_config()[key],
    }
    if field_type in {"text", "password", "number"}:
        field["control"] = "input"
        field["input_type"] = field_type
    if options is not None:
        field["options"] = options
    if visible is not None:
        field["visible"] = visible
        # Keep an explicit alias for simple V2 renderers that do not understand
        # the structured condition yet.
        field["visible_condition"] = visible
    if help_:
        field["help"] = help_
    return field


def build_global_config_schema() -> dict:
    """返回 Streamlit 当前暴露的全局设置的前端可消费 schema。

    Schema 只是 UI 元数据，运行时仍由 config_builder 使用 canonical
    global_config 生成配置；因此新增字段不会引入运行时依赖。
    """
    desktop = {"key": "is_desktop", "equals": True}
    tun = {"key": "enable_tun", "equals": True}
    dns = {"key": "enable_dns", "equals": True}
    controller = {"key": "include_controller", "equals": True}
    core = {"key": "enable_core_options", "equals": True}
    sniffer = {"key": "enable_sniffer", "equals": True}
    schema = {
        "optional_globals_v2": _global_schema_field("optional_globals_v2", "启用扩展全局设置", "checkbox"),
        "generation_profile": _global_schema_field(
            "generation_profile", "生成模式", "select", options=["openclash-router", "desktop-full", "minimal"]
        ),
        "is_desktop": _global_schema_field("is_desktop", "桌面客户端模式", "checkbox"),
        "include_inbound_ports": _global_schema_field("include_inbound_ports", "输出入站端口", "checkbox", visible=desktop),
        "include_global_compat": _global_schema_field("include_global_compat", "兼容 global 字段", "checkbox", visible=desktop),
        "include_controller": _global_schema_field("include_controller", "输出外部控制器", "checkbox", visible=desktop),
        "include_router_options": _global_schema_field("include_router_options", "输出路由选项", "checkbox", visible=desktop),
        "enable_core_options": _global_schema_field("enable_core_options", "输出核心选项", "checkbox", visible=desktop),
        "port": _global_schema_field("port", "HTTP 端口", "number", visible=desktop),
        "socks_port": _global_schema_field("socks_port", "Socks 端口", "number", visible=desktop),
        "mixed_port": _global_schema_field("mixed_port", "Mixed 端口", "number", visible=desktop),
        "allow_lan": _global_schema_field("allow_lan", "允许局域网访问", "checkbox", visible=desktop),
        "bind_address": _global_schema_field("bind_address", "绑定地址", "text", visible=desktop),
        "mode": _global_schema_field("mode", "运行模式", "select", options=["rule", "global", "direct"], visible=desktop),
        "log_level": _global_schema_field("log_level", "日志级别", "select", options=["info", "warning", "error", "debug", "silent"], visible=desktop),
        "ipv6_support": _global_schema_field("ipv6_support", "IPv6", "checkbox", visible=desktop),
        "external_controller": _global_schema_field("external_controller", "外部控制器地址", "text", visible=controller),
        "secret": _global_schema_field("secret", "外部控制器密钥", "password", visible=controller),
        "external_ui": _global_schema_field("external_ui", "外部 UI 路径", "text", visible=controller),
        "external_ui_name": _global_schema_field("external_ui_name", "外部 UI 名称", "text", visible=controller),
        "external_ui_url": _global_schema_field("external_ui_url", "外部 UI 地址", "text", visible=controller),
        "find_process_mode": _global_schema_field("find_process_mode", "进程匹配模式", "select", options=["strict", "always", "off"], visible=desktop),
        "url_test_url": _global_schema_field("url_test_url", "测速 URL", "text"),
        "url_test_interval": _global_schema_field("url_test_interval", "测速间隔", "number"),
        "url_test_tolerance": _global_schema_field("url_test_tolerance", "测速容差", "number"),
        "tcp_concurrent": _global_schema_field("tcp_concurrent", "TCP 并发", "checkbox", visible=core),
        "unified_delay": _global_schema_field("unified_delay", "统一延迟", "checkbox", visible=core),
        "enable_tun": _global_schema_field("enable_tun", "启用 TUN", "checkbox", visible=desktop),
        "tun_stack": _global_schema_field("tun_stack", "TUN 协议栈", "select", options=["gvisor", "system", "mixed"], visible=tun),
        "tun_device": _global_schema_field("tun_device", "TUN 设备", "text", visible=tun),
        "tun_auto_route": _global_schema_field("tun_auto_route", "自动路由", "checkbox", visible=tun),
        "tun_auto_detect_interface": _global_schema_field("tun_auto_detect_interface", "自动检测接口", "checkbox", visible=tun),
        "tun_dns_hijack": _global_schema_field("tun_dns_hijack", "DNS 劫持", "checkbox", visible=tun),
        "tun_dns_hijack_value": _global_schema_field("tun_dns_hijack_value", "DNS 劫持目标", "text", visible=tun),
        "tun_endpoint_independent_nat": _global_schema_field("tun_endpoint_independent_nat", "端点独立 NAT", "checkbox", visible=tun),
        "tun_auto_redirect": _global_schema_field("tun_auto_redirect", "自动重定向", "checkbox", visible=tun),
        "tun_strict_route": _global_schema_field("tun_strict_route", "严格路由", "checkbox", visible=tun),
        "enable_dns": _global_schema_field("enable_dns", "启用 DNS", "checkbox", visible=desktop),
        "dns_listen": _global_schema_field("dns_listen", "DNS 监听", "text", visible=dns),
        "dns_ipv6": _global_schema_field("dns_ipv6", "DNS IPv6", "checkbox", visible=dns),
        "enhanced_mode": _global_schema_field("enhanced_mode", "增强模式", "select", options=["fake-ip", "redir-host"], visible=dns),
        "fake_ip_range": _global_schema_field("fake_ip_range", "Fake-IP 网段", "text", visible=dns),
        "fake_ip_range6": _global_schema_field("fake_ip_range6", "Fake-IP IPv6 网段", "text", visible=dns),
        "fake_ip_filter_mode": _global_schema_field("fake_ip_filter_mode", "Fake-IP 过滤模式", "select", options=["blacklist", "whitelist"], visible=dns),
        "dns_respect_rules": _global_schema_field("dns_respect_rules", "DNS 遵循规则", "checkbox", visible=dns),
        "direct_nameserver": _global_schema_field("direct_nameserver", "直连 DNS", "textarea", visible=dns),
        "proxy_server_nameserver": _global_schema_field("proxy_server_nameserver", "代理 DNS", "textarea", visible=dns),
        "default_nameserver": _global_schema_field("default_nameserver", "Bootstrap DNS", "textarea", visible=dns),
        "nameserver": _global_schema_field("nameserver", "主要 DNS", "textarea", visible=dns),
        "fallback": _global_schema_field("fallback", "Fallback DNS", "textarea", visible=dns),
        "nameserver_policy": _global_schema_field("nameserver_policy", "DNS 策略", "textarea", visible=dns),
        "enable_sniffer": _global_schema_field("enable_sniffer", "启用嗅探", "checkbox", visible=desktop),
        "sniff_override_dest": _global_schema_field("sniff_override_dest", "嗅探覆盖目标", "checkbox", visible=sniffer),
        "sniffer_parse_pure_ip": _global_schema_field("sniffer_parse_pure_ip", "嗅探纯 IP", "checkbox", visible=sniffer),
        "sniffer_force_dns_mapping": _global_schema_field("sniffer_force_dns_mapping", "强制 DNS 映射", "checkbox", visible=sniffer),
        "openclash_preset": _global_schema_field("openclash_preset", "OpenClash 预设", "checkbox"),
        "profile_store_selected": _global_schema_field("profile_store_selected", "保存选中策略", "checkbox", visible=desktop),
        "profile_store_fake_ip": _global_schema_field("profile_store_fake_ip", "保存 Fake-IP", "checkbox", visible=desktop),
        "ntp_enable": _global_schema_field("ntp_enable", "启用 NTP", "checkbox", visible=desktop),
        "ntp_server": _global_schema_field("ntp_server", "NTP 服务器", "text", visible=desktop),
        "ntp_port": _global_schema_field("ntp_port", "NTP 端口", "number", visible=desktop),
        "ntp_interval": _global_schema_field("ntp_interval", "NTP 间隔", "number", visible=desktop),
        "ntp_write_to_system": _global_schema_field("ntp_write_to_system", "写入系统时间", "checkbox", visible=desktop),
        "authentication": _global_schema_field("authentication", "认证用户", "textarea", visible=desktop),
        "keep_alive_interval": _global_schema_field("keep_alive_interval", "保活间隔", "number", visible=desktop),
        "keep_alive_idle": _global_schema_field("keep_alive_idle", "保活空闲时间", "number", visible=desktop),
        "redir_port": _global_schema_field("redir_port", "Redir 端口", "number", visible=desktop),
        "tproxy_port": _global_schema_field("tproxy_port", "TProxy 端口", "number", visible=desktop),
        "interface_name": _global_schema_field("interface_name", "网络接口", "text", visible=desktop),
        "geodata_mode": _global_schema_field("geodata_mode", "GeoData 模式", "checkbox", visible=core),
        "geodata_loader": _global_schema_field("geodata_loader", "GeoData 加载器", "select", options=["standard", "memconservative"], visible=core),
        "lhie1_provider_targets": _global_schema_field("lhie1_provider_targets", "lhie1 目标覆盖", "textarea"),
        "dustinwin_provider_targets": _global_schema_field("dustinwin_provider_targets", "DustinWin 目标覆盖", "textarea"),
    }
    return schema


GLOBAL_CONFIG_SCHEMA = build_global_config_schema()
