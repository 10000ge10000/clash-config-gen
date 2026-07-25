import unittest

import yaml

from config_builder import (
    DUSTINWIN_PROVIDERS_MAP,
    DEFAULT_RULE_TYPE,
    DUSTINWIN_RULESET_INTERVAL,
    LHIE1_PROVIDERS_MAP,
    SUBSCRIPTION_GENERATOR,
    SUBSCRIPTION_GITHUB_URL,
    SUBSCRIPTION_PROJECT,
    SUBSCRIPTION_PROJECT_URL,
    SUBSCRIPTION_USAGE,
    build_config,
    build_rules,
    build_yaml,
    validate_config,
)
from clash_meta_gen import generate_proxy_groups
from importers import parse_share_link
from normalizer import normalize_proxy_for_mihomo


class ValidateConfigTest(unittest.TestCase):
    def test_browser_fingerprint_is_moved_to_client_fingerprint(self):
        """旧字段 fingerprint=chrome 会让 mihomo 当成证书固定并拒绝加载。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "hy2",
                "type": "hysteria2",
                "server": "example.com",
                "port": 443,
                "password": "secret",
                "fingerprint": "chrome",
            }
        )

        self.assertNotIn("fingerprint", proxy)
        self.assertEqual("chrome", proxy["client-fingerprint"])

    def test_invalid_fingerprint_is_removed(self):
        """无法识别为 SHA256 证书固定的 fingerprint 直接移除，避免内核硬失败。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "hy2",
                "type": "hysteria2",
                "server": "example.com",
                "port": 443,
                "password": "secret",
                "fingerprint": "not-a-cert-pin",
            }
        )

        self.assertNotIn("fingerprint", proxy)

    def test_ipv6_server_brackets_are_removed(self):
        """IPv6 server 应保存为裸地址，不能带 URL 风格方括号。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "anytls-ipv6",
                "type": "anytls",
                "server": "[2a0e:97c0:3f4:1::27e]",
                "port": 9530,
                "password": "secret",
            }
        )

        self.assertEqual("2a0e:97c0:3f4:1::27e", proxy["server"])

    def test_ipv6_server_yaml_list_is_unwrapped(self):
        """未加引号的 [IPv6] 会被 YAML 解析成列表，导入时必须收敛回裸地址。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "anytls-ipv6",
                "type": "anytls",
                "server": ["2a0e:97c0:3f4:1::27e"],
                "port": 9530,
                "password": "secret",
            }
        )

        self.assertEqual("2a0e:97c0:3f4:1::27e", proxy["server"])

    def test_legacy_ipv6_server_list_string_is_unwrapped(self):
        """历史数据里已经污染成 ['IPv6'] 字符串的 server 也要修复成裸地址。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "anytls-ipv6",
                "type": "anytls",
                "server": "['2a0e:97c0:3f4:1::27e']",
                "port": 9530,
                "password": "secret",
            }
        )

        self.assertEqual("2a0e:97c0:3f4:1::27e", proxy["server"])

    def test_shadowsocks_ipv6_server_uses_bare_literal(self):
        """SS 的 IPv6 server 应输出裸地址。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "ss-ipv6",
                "type": "ss",
                "server": "[2a0e:97c0:3f4:1::9ce]",
                "port": 9529,
                "cipher": "2022-blake3-aes-128-gcm",
                "password": "secret",
            }
        )

        self.assertEqual("2a0e:97c0:3f4:1::9ce", proxy["server"])

    def test_build_config_normalizes_proxies_before_yaml_output(self):
        """生成订阅时也要兜底清洗，保证数据库里的旧节点不会继续污染 YAML。"""
        config = build_config(
            [
                {
                    "name": "hy2",
                    "type": "hysteria2",
                    "server": "example.com",
                    "port": 443,
                    "password": "secret",
                    "fingerprint": "firefox",
                }
            ],
            {},
        )

        self.assertNotIn("fingerprint", config["proxies"][0])
        self.assertEqual("firefox", config["proxies"][0]["client-fingerprint"])

    def test_masque_h3_l4proxy_removes_tunnel_fields_and_disables_udp(self):
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "预制masque",
                "type": "masque",
                "server": "saas.sin.fan",
                "port": 443,
                "private-key": "private",
                "public-key": "public",
                "network": "h3-l4proxy",
                "sni": "consumer-masque-proxy.cloudflareclient.com",
                "udp": True,
                "ip": "172.16.0.2/32",
                "ipv6": "2606:4700::1/128",
                "mtu": 1280,
            }
        )

        self.assertIs(False, proxy["udp"])
        self.assertNotIn("ip", proxy)
        self.assertNotIn("ipv6", proxy)
        self.assertNotIn("mtu", proxy)

    def test_build_config_strips_internal_import_source_metadata(self):
        """导入来源只用于管理界面，不能泄漏到最终订阅 YAML。"""
        config = build_config(
            [
                {
                    "name": "node-1",
                    "type": "ss",
                    "server": "127.0.0.1",
                    "port": 8388,
                    "cipher": "aes-128-gcm",
                    "password": "password",
                    "_source_id": "source-1",
                    "_source_name": "远程订阅",
                    "_origin_name": "原始节点",
                }
            ],
            {},
        )

        self.assertEqual("node-1", config["proxies"][0]["name"])
        self.assertFalse(
            any(key.startswith("_") for key in config["proxies"][0]),
        )

    def test_hysteria2_hop_interval_range_is_normalized_to_int(self):
        """OpenClash 当前按整数解析 hop-interval，旧数据里的 5-25 必须收敛为 5。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "hy2",
                "type": "hysteria2",
                "server": "example.com",
                "port": 443,
                "password": "secret",
                "ports": "20000-50000",
                "hop-interval": "5-25",
            }
        )

        self.assertEqual(5, proxy["hop-interval"])

    def test_invalid_hysteria2_hop_interval_is_removed(self):
        """无法转成正整数秒的 hop-interval 直接移除，避免 mihomo 启动时硬失败。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "hy2",
                "type": "hysteria2",
                "server": "example.com",
                "port": 443,
                "password": "secret",
                "hop-interval": "fast",
            }
        )

        self.assertNotIn("hop-interval", proxy)

    def test_anytls_ech_opts_are_preserved_and_normalized(self):
        """AnyTLS ECH 必须输出 mihomo 官方 ech-opts 结构。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "anytls-ech",
                "type": "anytls",
                "server": "example.com",
                "port": 443,
                "password": "secret",
                "ech-opts": {
                    "enable": "true",
                    "config": "  AEn+DQBFKwAgAA  ",
                    "query-server-name": "  public.tls-ech.dev  ",
                },
            }
        )

        self.assertEqual(
            {
                "enable": True,
                "config": "AEn+DQBFKwAgAA",
                "query-server-name": "public.tls-ech.dev",
            },
            proxy["ech-opts"],
        )

    def test_anytls_ech_without_config_keeps_enable_only(self):
        """ECH config 可留空，留空时交给 mihomo 通过 DNS 获取。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "anytls-ech",
                "type": "anytls",
                "server": "example.com",
                "port": 443,
                "password": "secret",
                "ech-opts": {
                    "enable": 1,
                    "config": "",
                    "query-server-name": " ",
                },
            }
        )

        self.assertEqual({"enable": True}, proxy["ech-opts"])

    def test_invalid_ech_opts_are_removed(self):
        """错误类型的 ech-opts 不能污染最终订阅。"""
        proxy = normalize_proxy_for_mihomo(
            {
                "name": "anytls-ech",
                "type": "anytls",
                "server": "example.com",
                "port": 443,
                "password": "secret",
                "ech-opts": "enabled",
            }
        )

        self.assertNotIn("ech-opts", proxy)

    def test_anytls_share_link_imports_ech_opts(self):
        """分享链接的兼容 ECH 参数应映射成 mihomo 官方 ech-opts。"""
        proxy = parse_share_link(
            "anytls://secret@example.com:443?ech=1&ech_config=AEn%2Btest&ech-query-server-name=public.tls-ech.dev"
        )
        proxy = normalize_proxy_for_mihomo(proxy)

        self.assertEqual(
            {
                "enable": True,
                "config": "AEn+test",
                "query-server-name": "public.tls-ech.dev",
            },
            proxy["ech-opts"],
        )

    def test_vmess_ws_brutal_fields_survive_build_config(self):
        """VMess WS + Brutal 依赖 ws-opts 与 smux.brutal-opts，生成订阅不能丢字段。"""
        config = build_config(
            [
                {
                    "name": "vmess-ws-brutal",
                    "type": "vmess",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "00000000-0000-4000-8000-000000000000",
                    "alterId": 0,
                    "cipher": "auto",
                    "tls": True,
                    "network": "ws",
                    "ws-opts": {
                        "path": "/ws",
                        "headers": {"Host": "example.com"},
                    },
                    "smux": {
                        "enabled": True,
                        "protocol": "h2mux",
                        "max-connections": 4,
                        "brutal-opts": {
                            "enabled": True,
                            "up": "100 Mbps",
                            "down": "100 Mbps",
                        },
                    },
                }
            ],
            {},
        )

        proxy = config["proxies"][0]
        self.assertEqual("ws", proxy["network"])
        self.assertEqual("/ws", proxy["ws-opts"]["path"])
        self.assertEqual("example.com", proxy["ws-opts"]["headers"]["Host"])
        self.assertTrue(proxy["smux"]["brutal-opts"]["enabled"])
        self.assertEqual("100 Mbps", proxy["smux"]["brutal-opts"]["up"])
        self.assertEqual("100 Mbps", proxy["smux"]["brutal-opts"]["down"])

    def test_empty_proxy_groups_are_rejected(self):
        """没有策略组的配置会让客户端只剩内置 Global，必须在保存前拦住。"""
        errors, warnings = validate_config(
            {
                "proxies": [
                    {
                        "name": "node-1",
                        "type": "ss",
                        "server": "127.0.0.1",
                        "port": 8388,
                        "cipher": "aes-128-gcm",
                        "password": "password",
                    }
                ],
                "proxy-groups": [],
                "rules": ["MATCH,Proxy"],
            }
        )

        self.assertIn("Proxy Groups 为空", errors)
        self.assertIn("规则 'MATCH,Proxy' 指向了不存在的策略组: 'Proxy'", errors)
        self.assertEqual([], warnings)

    def test_no_resolve_rule_target_uses_penultimate_field(self):
        """带 no-resolve 的规则，策略组目标在倒数第二段，不能误读成 no-resolve。"""
        errors, warnings = validate_config(
            {
                "proxies": [
                    {
                        "name": "node-1",
                        "type": "ss",
                        "server": "127.0.0.1",
                        "port": 8388,
                        "cipher": "aes-128-gcm",
                        "password": "password",
                    }
                ],
                "proxy-groups": [
                    {"name": "Proxy", "type": "select", "proxies": ["node-1"]},
                ],
                "rules": ["GEOIP,CN,Domestic,no-resolve", "MATCH,Proxy"],
            }
        )

        self.assertIn("规则 'GEOIP,CN,Domestic,no-resolve' 指向了不存在的策略组: 'Domestic'", errors)
        self.assertEqual([], warnings)

    def test_no_resolve_rule_accepts_existing_target(self):
        """策略组存在时，GEOIP/CIDR 这类 no-resolve 规则不应产生误报。"""
        errors, warnings = validate_config(
            {
                "proxies": [
                    {
                        "name": "node-1",
                        "type": "ss",
                        "server": "127.0.0.1",
                        "port": 8388,
                        "cipher": "aes-128-gcm",
                        "password": "password",
                    }
                ],
                "proxy-groups": [
                    {"name": "Proxy", "type": "select", "proxies": ["node-1"]},
                    {"name": "Domestic", "type": "select", "proxies": ["DIRECT", "Proxy"]},
                ],
                "rules": ["GEOIP,CN,Domestic,no-resolve", "MATCH,Proxy"],
            }
        )

        self.assertEqual([], errors)
        self.assertEqual([], warnings)

    def test_protocol_required_fields_are_enforced(self):
        """协议级必填字段缺失时必须阻止保存，避免把坏配置交给 OpenClash。"""
        errors, _warnings = validate_config(
            {
                "proxies": [
                    {
                        "name": "broken-ss",
                        "type": "ss",
                        "server": "127.0.0.1",
                        "port": 8388,
                    }
                ],
                "proxy-groups": [
                    {"name": "Proxy", "type": "select", "proxies": ["broken-ss"]},
                ],
                "rules": ["MATCH,Proxy"],
            }
        )

        self.assertIn("节点 'broken-ss' 缺少必填字段: cipher, password", errors)

    def test_openclash_router_profile_strips_plugin_managed_runtime_fields(self):
        """OpenClash 会接管端口、DNS、控制器等字段，订阅模板不能重复输出。"""
        config = build_config(
            [
                {
                    "name": "node-1",
                    "type": "ss",
                    "server": "127.0.0.1",
                    "port": 8388,
                    "cipher": "aes-128-gcm",
                    "password": "password",
                }
            ],
            {
                "generation_profile": "openclash-router",
                "include_global_compat": True,
                "include_inbound_ports": True,
                "include_controller": True,
                "include_router_options": True,
                "enable_core_options": True,
                "enable_dns": True,
                "enable_tun": True,
                "enable_sniffer": True,
                "profile_store_selected": True,
                "profile_store_fake_ip": True,
                "ntp_enable": True,
                "authentication": "user:pass",
                "redir_port": 7892,
                "tproxy_port": 7895,
                "external_controller": "0.0.0.0:9090",
                "secret": "secret",
            },
        )

        blocked_keys = {
            "global",
            "port",
            "socks-port",
            "mixed-port",
            "redir-port",
            "tproxy-port",
            "external-controller",
            "secret",
            "dns",
            "tun",
            "sniffer",
            "profile",
            "ntp",
            "authentication",
            "tcp-concurrent",
            "unified-delay",
            "geodata-mode",
            "geodata-loader",
        }
        self.assertTrue(blocked_keys.isdisjoint(config.keys()))
        self.assertIn("proxy-groups", config)
        self.assertIn("rules", config)

    def test_target_mode_overrides_legacy_generation_profile(self):
        """旧库里残留的 generation_profile 不能覆盖用户当前选择的使用场景。"""
        config = build_config(
            [
                {
                    "name": "node-1",
                    "type": "ss",
                    "server": "127.0.0.1",
                    "port": 8388,
                    "cipher": "aes-128-gcm",
                    "password": "password",
                }
            ],
            {
                "is_desktop": False,
                "generation_profile": "desktop-full",
                "enable_dns": True,
                "enable_tun": True,
                "enable_sniffer": True,
            },
        )

        self.assertNotIn("dns", config)
        self.assertNotIn("tun", config)
        self.assertNotIn("sniffer", config)

    def test_lhie1_media_defaults_use_specific_policy_groups_when_available(self):
        """已有独立策略组的媒体规则必须先进独立组，手动选择节点才会生效。"""
        rules, _providers = build_rules("lhie1规则", [], {})
        expected_rules = {
            "RULE-SET,Netflix,Netflix",
            "RULE-SET,Disney Plus,Disney Plus",
            "RULE-SET,Max,HBO Max",
            "RULE-SET,YouTube,Youtube",
            "RULE-SET,Bilibili,Bilibili",
            "RULE-SET,IQIYI,CN Mainland TV",
            "RULE-SET,Abema TV,Asian TV",
            "RULE-SET,Bahamut,Bahamut",
            "RULE-SET,Apple TV,Apple TV",
            "RULE-SET,Telegram,Telegram",
        }

        for expected_rule in expected_rules:
            self.assertIn(expected_rule, rules)

    def test_lhie1_default_targets_exist_in_generated_proxy_groups(self):
        """LHIE1 默认目标必须是内置动作或生成器实际存在的策略组。"""
        proxies = [
            {
                "name": "node-1",
                "type": "ss",
                "server": "127.0.0.1",
                "port": 8388,
                "cipher": "aes-128-gcm",
                "password": "password",
            }
        ]
        group_names = {group["name"] for group in generate_proxy_groups(proxies)}
        builtin_targets = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "Proxy"}

        for provider_name, (_suffix, target) in LHIE1_PROVIDERS_MAP.items():
            self.assertIn(target, group_names | builtin_targets, provider_name)

    def test_dustinwin_ai_ruleset_targets_ai_suite(self):
        """DustinWin 的 ai.mrs 必须进入 AI Suite，避免 Gemini 等 AI 域名漏分流。"""
        rules, providers = build_rules("dustinwin规则", [], {})

        self.assertIn("RULE-SET,ai,AI Suite", rules)
        self.assertEqual("domain", providers["ai"]["behavior"])
        self.assertEqual("mrs", providers["ai"]["format"])
        self.assertEqual(DUSTINWIN_RULESET_INTERVAL, providers["ai"]["interval"])
        self.assertTrue(providers["ai"]["url"].endswith("/ruleset/dustinwin/ai.mrs"))
        self.assertEqual("./ruleset/dustinwin/ai.mrs", providers["ai"]["path"])

    def test_dustinwin_ai_rules_precede_domestic_rules(self):
        """AI 域名规则必须早于国内域名和国内 IP，避免污染 IP 抢先直连。"""
        rules, _providers = build_rules("dustinwin规则", [], {})

        ai_index = rules.index("RULE-SET,ai,AI Suite")
        self.assertLess(ai_index, rules.index("RULE-SET,cn,Domestic"))
        self.assertLess(ai_index, rules.index("RULE-SET,cnip,Domestic,no-resolve"))

    def test_lhie1_ai_suite_rules_precede_domestic_rules(self):
        """LHIE1 的 AI Suite 必须早于 Domestic / Domestic IPs。"""
        rules, _providers = build_rules("lhie1规则", [], {})

        ai_index = rules.index("RULE-SET,AI Suite,AI Suite")
        self.assertLess(ai_index, rules.index("RULE-SET,Domestic,Domestic"))
        self.assertLess(ai_index, rules.index("RULE-SET,Domestic IPs,Domestic"))
        self.assertLess(ai_index, rules.index("GEOIP,CN,Domestic,no-resolve"))

    def test_lhie1_specific_service_rules_precede_domestic_fallbacks(self):
        """LHIE1 专项服务规则必须早于国内域名/IP 兜底。"""
        rules, _providers = build_rules("lhie1规则", [], {})
        domestic_index = rules.index("RULE-SET,Domestic,Domestic")
        domestic_ips_index = rules.index("RULE-SET,Domestic IPs,Domestic")

        for expected_rule in [
            "RULE-SET,Netflix,Netflix",
            "RULE-SET,YouTube,Youtube",
            "RULE-SET,Disney Plus,Disney Plus",
            "RULE-SET,Telegram,Telegram",
            "RULE-SET,TikTok,TikTok",
            "RULE-SET,Microsoft,Microsoft",
            "RULE-SET,Apple,Apple",
            "RULE-SET,Google FCM,Google FCM",
        ]:
            rule_index = rules.index(expected_rule)
            self.assertLess(rule_index, domestic_index, expected_rule)
            self.assertLess(rule_index, domestic_ips_index, expected_rule)

    def test_dustinwin_media_rules_target_specific_policy_groups_when_available(self):
        """YouTube/Netflix 等规则应进入同名策略组，未手动选择时由该组默认回落到 Global TV。"""
        rules, _providers = build_rules("dustinwin规则", [], {})
        expected_rules = {
            "RULE-SET,youtube,Youtube",
            "RULE-SET,netflix,Netflix",
            "RULE-SET,netflixip,Netflix,no-resolve",
            "RULE-SET,disney,Disney Plus",
            "RULE-SET,max,HBO Max",
            "RULE-SET,spotify,Spotify",
            "RULE-SET,bilibili,Bilibili",
            "RULE-SET,media,Global TV",
            "RULE-SET,mediaip,Global TV,no-resolve",
        }

        for expected_rule in expected_rules:
            self.assertIn(expected_rule, rules)

    def test_build_config_defaults_to_dustinwin_ruleset(self):
        """默认生成路径必须使用 DustinWin，避免新用户跳过分流页时漏掉 AI/Gemini。"""
        config = build_config(
            [
                {
                    "name": "node-1",
                    "type": "ss",
                    "server": "127.0.0.1",
                    "port": 8388,
                    "cipher": "aes-128-gcm",
                    "password": "password",
                }
            ],
            {},
        )

        self.assertEqual("dustinwin规则", DEFAULT_RULE_TYPE)
        self.assertIn("RULE-SET,ai,AI Suite", config["rules"])
        self.assertIn("ai", config["rule-providers"])

    def test_dustinwin_default_targets_exist_in_generated_proxy_groups(self):
        """DustinWin 默认目标必须是内置动作或生成器实际存在的策略组。"""
        proxies = [
            {
                "name": "node-1",
                "type": "ss",
                "server": "127.0.0.1",
                "port": 8388,
                "cipher": "aes-128-gcm",
                "password": "password",
            }
        ]
        group_names = {group["name"] for group in generate_proxy_groups(proxies)}
        builtin_targets = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "Proxy"}

        for provider_name, provider_config in DUSTINWIN_PROVIDERS_MAP.items():
            self.assertIn(provider_config["target"], group_names | builtin_targets, provider_name)

    def test_dustinwin_ipcidr_rules_use_no_resolve(self):
        """ipcidr 规则集应显式 no-resolve，减少 DNS 侧副作用。"""
        rules, providers = build_rules("dustinwin规则", [], {})

        self.assertIn("RULE-SET,telegramip,Telegram,no-resolve", rules)
        self.assertIn("RULE-SET,privateip,DIRECT,no-resolve", rules)
        self.assertEqual("ipcidr", providers["telegramip"]["behavior"])
        self.assertEqual("mrs", providers["telegramip"]["format"])

    def test_dustinwin_specific_ip_rules_precede_domestic_ip_fallback(self):
        """专项 IP 规则应早于 cnip，避免被国内 IP 兜底抢先命中。"""
        rules, _providers = build_rules("dustinwin规则", [], {})
        cnip_index = rules.index("RULE-SET,cnip,Domestic,no-resolve")

        for expected_rule in [
            "RULE-SET,telegramip,Telegram,no-resolve",
            "RULE-SET,netflixip,Netflix,no-resolve",
            "RULE-SET,mediaip,Global TV,no-resolve",
        ]:
            self.assertLess(rules.index(expected_rule), cnip_index, expected_rule)

    def test_media_policy_groups_default_to_aggregate_selectors(self):
        """独立流媒体策略组的默认选中项要和 LHIE1 聚合规则目标一致。"""
        proxies = [
            {
                "name": "node-1",
                "type": "ss",
                "server": "127.0.0.1",
                "port": 8388,
                "cipher": "aes-128-gcm",
                "password": "password",
            }
        ]
        groups = {group["name"]: group for group in generate_proxy_groups(proxies)}

        for group_name in ["Netflix", "Disney Plus", "Discovery Plus", "DAZN", "Spotify", "HBO Max", "Youtube"]:
            self.assertEqual("Global TV", groups[group_name]["proxies"][0], group_name)
        self.assertEqual("CN Mainland TV", groups["Bilibili"]["proxies"][0])
        self.assertEqual("Asian TV", groups["Bahamut"]["proxies"][0])
        self.assertEqual("Proxy", groups["Steam"]["proxies"][0])
        self.assertEqual("Proxy", groups["Pornhub"]["proxies"][0])

    def test_url_test_defaults_are_written_to_proxy_group(self):
        """默认 URL-Test 参数应写入订阅 YAML，供 Nikki/OpenClash 等客户端读取。"""
        config = build_config(
            [
                {
                    "name": "node-1",
                    "type": "ss",
                    "server": "127.0.0.1",
                    "port": 8388,
                    "cipher": "aes-128-gcm",
                    "password": "password",
                }
            ],
            {},
        )
        groups = {group["name"]: group for group in config["proxy-groups"]}

        self.assertEqual("http://cp.cloudflare.com/generate_204", groups["Auto - UrlTest"]["url"])
        self.assertEqual(60, groups["Auto - UrlTest"]["interval"])
        self.assertEqual(30, groups["Auto - UrlTest"]["tolerance"])

    def test_url_test_settings_can_be_overridden_by_global_config(self):
        """全局设置里的 URL-Test 参数必须覆盖默认值。"""
        config = build_config(
            [
                {
                    "name": "node-1",
                    "type": "ss",
                    "server": "127.0.0.1",
                    "port": 8388,
                    "cipher": "aes-128-gcm",
                    "password": "password",
                }
            ],
            {
                "url_test_url": "https://www.gstatic.com/generate_204",
                "url_test_interval": 120,
                "url_test_tolerance": 30,
            },
        )
        groups = {group["name"]: group for group in config["proxy-groups"]}

        self.assertEqual("https://www.gstatic.com/generate_204", groups["Auto - UrlTest"]["url"])
        self.assertEqual(120, groups["Auto - UrlTest"]["interval"])
        self.assertEqual(30, groups["Auto - UrlTest"]["tolerance"])

    def test_generated_yaml_contains_non_sensitive_project_comments(self):
        """订阅 YAML 可以带项目说明注释，mihomo/OpenClash 解析时会自动忽略。"""
        config = {
            "proxies": [
                {
                    "name": "node-1",
                    "type": "ss",
                    "server": "127.0.0.1",
                    "port": 8388,
                    "cipher": "aes-128-gcm",
                    "password": "password",
                }
            ],
            "proxy-groups": [{"name": "Proxy", "type": "select", "proxies": ["node-1"]}],
            "rules": ["MATCH,Proxy"],
        }

        rendered = build_yaml(config)
        loaded = yaml.safe_load(rendered)

        self.assertTrue(rendered.startswith(f"# Generator: {SUBSCRIPTION_GENERATOR}\n"))
        self.assertIn(f"# Generator-URL: {SUBSCRIPTION_GITHUB_URL}", rendered)
        self.assertIn(f"# Project: {SUBSCRIPTION_PROJECT}", rendered)
        self.assertIn(f"# Project-URL: {SUBSCRIPTION_PROJECT_URL}", rendered)
        self.assertIn(f"# Usage: {SUBSCRIPTION_USAGE}", rendered)
        self.assertEqual(config, loaded)


if __name__ == "__main__":
    unittest.main()
