import os
import unittest
from unittest import mock

import yaml

from config_builder import (
    DUSTINWIN_PROVIDERS_MAP,
    DEFAULT_RULE_TYPE,
    DUSTINWIN_RULESET_INTERVAL,
    GOOGLE_RULESET_FILE,
    GOOGLE_RULESET_URL,
    SUBSCRIPTION_GENERATOR,
    SUBSCRIPTION_GITHUB_URL,
    SUBSCRIPTION_PROJECT,
    SUBSCRIPTION_PROJECT_URL,
    SUBSCRIPTION_USAGE,
    build_config,
    build_rule_catalog,
    build_rules,
    build_yaml,
    validate_config,
)
from clash_meta_gen import generate_proxy_groups
from importers import parse_proxy_yaml, parse_share_link
from normalizer import normalize_proxy_for_mihomo


class RuleOrderTest(unittest.TestCase):
    def test_custom_match_goes_last_and_replaces_preset_fallback(self):
        rules, _ = build_rules("dustinwin规则", ["MATCH,A", "DOMAIN,x.com,B", "match,C"], {})
        self.assertEqual(rules[0], "DOMAIN,x.com,B")
        self.assertEqual(rules[-1], "MATCH,A")
        self.assertEqual(sum(rule.upper().startswith("MATCH,") for rule in rules), 1)

    def test_rulesets_stay_between_custom_rules_and_fallback(self):
        providers = {
            "first": {"type": "http", "url": "https://example.com/a.yaml", "target": "A", "order": "优先 (覆盖)"},
            "last": {"type": "http", "url": "https://example.com/b.yaml", "target": "B", "order": "追加"},
        }
        rules, _ = build_rules("dustinwin规则", ["DOMAIN,x.com,C", "MATCH,D"], providers)
        self.assertEqual(rules[:2], ["DOMAIN,x.com,C", "RULE-SET,first,A"])
        self.assertEqual(rules[-2:], ["RULE-SET,last,B", "MATCH,D"])

    def test_no_base_source_keeps_only_user_rules(self):
        self.assertEqual(build_rules("none", ["DOMAIN,x.com,C"], {})[0], ["DOMAIN,x.com,C"])


class RuleCatalogTest(unittest.TestCase):
    def _rebuild(self, entry):
        parts = [entry["type"], entry["value"], entry["target"]]
        if entry["no_resolve"]:
            parts.append("no-resolve")
        return ",".join(parts)

    def test_catalog_matches_generated_rule_order(self):
        catalog = build_rule_catalog()
        for rule_type in ("dustinwin规则",):
            rules, _ = build_rules(rule_type, [], {})
            shown = [self._rebuild(entry) for entry in catalog[rule_type]["rules"]]
            shown.append("MATCH," + catalog[rule_type]["fallback"])
            self.assertEqual(shown, rules)

    def test_only_mapped_providers_are_overridable(self):
        catalog = build_rule_catalog()
        self.assertEqual({"dustinwin规则", "none"}, set(catalog))
        entries = {entry["value"]: entry for entry in catalog["dustinwin规则"]["rules"]}
        self.assertTrue(entries["ai"]["overridable"])
        self.assertTrue(entries["discord"]["overridable"])
        self.assertFalse(entries["xn--ngstr-lra8j.com"]["overridable"])

    def test_no_base_source_has_no_fallback(self):
        self.assertEqual(build_rule_catalog()["none"]["rules"], [])
        self.assertIsNone(build_rule_catalog()["none"]["fallback"])


class ValidateConfigTest(unittest.TestCase):
    def setUp(self):
        # 未设置 PUBLIC_BASE_URL 时规则集回退上游直链；缓存链接相关断言需显式给出公网地址。
        patcher = mock.patch.dict(os.environ, {"PUBLIC_BASE_URL": "https://sub.example.test"})
        patcher.start()
        self.addCleanup(patcher.stop)

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

    def test_masque_is_rejected_case_insensitively(self):
        config = build_config(
            [
                {
                    "name": "removed-protocol",
                    "type": "MaSqUe",
                    "server": "example.com",
                    "port": 443,
                    "private-key": "private",
                    "public-key": "public",
                }
            ],
            {},
        )

        errors, _warnings = validate_config(config)

        self.assertIn("不再支持 MASQUE 节点", "\n".join(errors))

    def test_masque_yaml_import_is_rejected(self):
        raw_yaml = """
proxies:
  - name: removed-protocol
    type: masque
    server: example.com
    port: 443
    private-key: private
    public-key: public
"""

        with self.assertRaisesRegex(ValueError, "没有解析出任何有效节点"):
            parse_proxy_yaml(raw_yaml)

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

    def test_legacy_lhie1_rule_type_uses_builtin_rules(self):
        """lhie1 规则源已并入内置规则：旧草稿里的 lhie1规则 生成与内置规则完全一致。"""
        self.assertEqual(build_rules("dustinwin规则", [], {}), build_rules("lhie1规则", [], {}))

    def test_every_policy_group_is_reachable(self):
        """每个策略组都要被规则或其他策略组用到，不能出现选了也没用的组。"""
        groups = generate_proxy_groups([{"name": "node-1", "type": "ss"}])
        rules, _providers = build_rules("dustinwin规则", [], {})
        used = {rule.split(",")[2] for rule in rules if rule.startswith("RULE-SET,")}
        used |= {rule.split(",")[-1] for rule in rules if not rule.startswith("RULE-SET,")}
        for group in groups:
            used |= set(group.get("proxies") or [])
        unused = [group["name"] for group in groups if group["name"] not in used]
        self.assertEqual([], unused)
        self.assertNotIn("HTTPDNS", {group["name"] for group in groups})

    def test_meta_rules_fill_specialty_groups_before_broad_lists(self):
        """MetaCubeX 补齐的专项规则集要指向各自策略组，并排在 media/gfw/proxy/cn 大名单之前。"""
        rules, providers = build_rules("dustinwin规则", [], {})
        expected = {
            "googlefcm": "Google FCM", "telegram": "Telegram", "discord": "Discord", "paypal": "PayPal",
            "crypto": "Crypto", "scholar": "Scholar", "mihoyo": "miHoYo", "abema": "Asian TV",
            "bahamut": "Bahamut", "dazn": "DAZN", "discoveryplus": "Discovery Plus", "pornhub": "Pornhub",
        }
        index = {rule.split(",")[1]: i for i, rule in enumerate(rules) if rule.startswith("RULE-SET,")}
        for name, target in expected.items():
            self.assertIn(f"RULE-SET,{name},{target}", rules)
            for broad in ("media", "tld-proxy", "gfw", "proxy", "cn"):
                self.assertLess(index[name], index[broad], f"{name} vs {broad}")
            self.assertEqual("domain", providers[name]["behavior"])
            self.assertEqual(f"./ruleset/dustinwin/{name}.mrs", providers[name]["path"])
            self.assertTrue(providers[name]["url"].endswith(f"/ruleset/dustinwin/{name}.mrs"))
        self.assertLess(index["googlefcm"], index["google-cn"])
        self.assertLess(index["scholar"], index["google"])
        self.assertEqual(
            "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-scholar-%21cn.mrs",
            DUSTINWIN_PROVIDERS_MAP["scholar"]["url"],
        )

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

    def test_google_policy_group_and_provider_are_generated(self):
        """Google 请求应进入独立策略组，YouTube 保持独立策略组。"""
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
        self.assertEqual("Proxy", groups["Google"]["proxies"][0])
        self.assertEqual("Global TV", groups["Youtube"]["proxies"][0])

        rules, providers = build_rules("dustinwin规则", [], {})
        self.assertIn("RULE-SET,google,Google", rules)
        self.assertIn("RULE-SET,google-cn,Domestic", rules)
        self.assertIn("RULE-SET,youtube,Youtube", rules)
        self.assertLess(rules.index("RULE-SET,youtube,Youtube"), rules.index("RULE-SET,google,Google"))
        self.assertEqual("classical", providers["google"]["behavior"])
        self.assertEqual("text", providers["google"]["format"])
        self.assertEqual(f"./ruleset/dustinwin/{GOOGLE_RULESET_FILE}", providers["google"]["path"])
        self.assertTrue(providers["google"]["url"].endswith(f"/ruleset/dustinwin/{GOOGLE_RULESET_FILE}"))

    def test_google_source_url_is_used_when_service_cache_is_disabled(self):
        """关闭服务端缓存时，Google 规则集应回退到真实上游 URL。"""
        from unittest.mock import patch

        with patch.dict("os.environ", {"RULESET_CACHE_ENABLED": "false"}, clear=False):
            _rules, providers = build_rules("dustinwin规则", [], {})
        self.assertEqual(GOOGLE_RULESET_URL, providers["google"]["url"])

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

    def test_youtube_group_keeps_udp(self):
        """Youtube 组不能 disable-udp：mihomo 会让 QUIC 跳过该规则，落到 media 走 Global TV。"""
        groups = {group["name"]: group for group in generate_proxy_groups([{"name": "node-1", "type": "ss"}])}

        for group in groups.values():
            self.assertNotIn("disable-udp", group, group["name"])

    def test_domestic_reachable_rulesets_default_to_direct(self):
        """国内可直连的规则集默认不能走代理。"""
        groups = {group["name"]: group for group in generate_proxy_groups([{"name": "node-1", "type": "ss"}])}
        rules, _providers = build_rules("dustinwin规则", [], {})

        self.assertIn("RULE-SET,microsoft-cn,Microsoft", rules)
        self.assertIn("RULE-SET,apple-cn,Apple", rules)
        self.assertEqual("DIRECT", groups["Microsoft"]["proxies"][0])
        self.assertEqual("DIRECT", groups["Apple"]["proxies"][0])
        # Google、Game 组还承接境外流量，保持代理；它们的国内集合改由 Domestic 承接。
        self.assertIn("RULE-SET,google-cn,Domestic", rules)
        self.assertIn("RULE-SET,games-cn,Domestic", rules)
        self.assertEqual("Proxy", groups["Google"]["proxies"][0])
        self.assertEqual("DIRECT", groups["Domestic"]["proxies"][0])

    def test_dustinwin_rule_order_avoids_shadowing(self):
        """完整 Google 列表不能抢在广告和国内集合之前；AI、YouTube 仍在广告前。"""
        rules, _providers = build_rules("dustinwin规则", [], {})
        index = {rule.split(",")[1]: i for i, rule in enumerate(rules) if rule.startswith("RULE-SET,")}

        self.assertEqual("private", rules[2].split(",")[1])
        self.assertLess(index["ai"], index["ads"])
        self.assertLess(index["youtube"], index["ads"])
        self.assertLess(index["youtube"], index["media"])
        for earlier in ("ads", "microsoft-cn", "apple-cn", "google-cn", "games-cn"):
            self.assertLess(index[earlier], index["google"], earlier)
        self.assertLess(index["google"], index["games"])
        self.assertEqual("cnip", max(index, key=index.get))

    def test_steam_group_renamed_to_game_with_legacy_references(self):
        """Steam 组已改名 Game：旧的自定义规则、规则集目标和目标覆盖里的 Steam 自动换成 Game。"""
        groups = {group["name"] for group in generate_proxy_groups([{"name": "node-1", "type": "ss"}])}
        self.assertIn("Game", groups)
        self.assertNotIn("Steam", groups)

        rules, _providers = build_rules(
            "dustinwin规则",
            ["DOMAIN-SUFFIX,example.com,Steam", "IP-CIDR,1.2.3.0/24,Steam,no-resolve"],
            {"mygames": {"type": "http", "behavior": "domain", "url": "https://example.com/a.yaml", "target": "Steam"}},
            dustinwin_provider_targets={"netflix": "Steam"},
        )
        self.assertIn("RULE-SET,games,Game", rules)
        self.assertIn("DOMAIN-SUFFIX,example.com,Game", rules)
        self.assertIn("IP-CIDR,1.2.3.0/24,Game,no-resolve", rules)
        self.assertIn("RULE-SET,mygames,Game", rules)
        self.assertIn("RULE-SET,netflix,Game", rules)
        self.assertFalse([rule for rule in rules if ",Steam" in rule])

    def test_custom_ipcidr_ruleset_gets_no_resolve_and_prepend_alias(self):
        """自定义 ipcidr 规则集默认 no-resolve；order 写 prepend 也按优先处理。"""
        rules, _providers = build_rules(
            "dustinwin规则",
            [],
            {
                "myip": {"type": "http", "behavior": "ipcidr", "url": "https://example.com/ip.yaml", "order": "prepend", "target": "Proxy"},
                "mydomain": {"type": "http", "behavior": "domain", "url": "https://example.com/d.yaml", "order": "追加", "target": "Proxy"},
            },
        )
        self.assertIn("RULE-SET,myip,Proxy,no-resolve", rules)
        self.assertIn("RULE-SET,mydomain,Proxy", rules)
        self.assertLess(rules.index("RULE-SET,myip,Proxy,no-resolve"), rules.index("RULE-SET,private,DIRECT"))
        self.assertGreater(rules.index("RULE-SET,mydomain,Proxy"), rules.index("RULE-SET,cnip,Domestic,no-resolve"))

    def test_lowercase_custom_match_replaces_fallback(self):
        """自定义兜底写成小写 match 时，不能再额外补一条 MATCH。"""
        rules, _providers = build_rules("dustinwin规则", ["match,DIRECT"], {})
        self.assertEqual("match,DIRECT", rules[-1])
        self.assertEqual(1, sum(1 for rule in rules if rule.lower().startswith("match,")))

    def test_validate_config_handles_rule_params_and_references(self):
        """目标判断要跳过 no-resolve/src 修饰并去空格；SUB-RULE 查子规则；RULE-SET 必须有对应规则集。"""
        base = {
            "proxies": [{"name": "node-1", "type": "ss", "server": "127.0.0.1", "port": 8388, "cipher": "aes-128-gcm", "password": "x"}],
            "proxy-groups": [{"name": "P", "type": "select", "proxies": ["node-1"]}],
            "rule-providers": {"known": {"type": "http", "behavior": "domain", "url": "https://example.com/a.yaml", "path": "./a.yaml"}},
            "sub-rules": {"sub1": ["MATCH,P"]},
        }
        valid_rules = [
            "DOMAIN,x.com,P,src",
            "IP-CIDR,1.0.0.0/8,P,no-resolve,src",
            "DOMAIN,a.com, P",
            "SUB-RULE,(NETWORK,TCP),sub1",
            "RULE-SET,known,P",
            "DOMAIN,b.com,GLOBAL",
            "MATCH,P",
        ]
        errors, _warnings = validate_config({**base, "rules": valid_rules})
        self.assertEqual([], errors)

        errors, _warnings = validate_config({**base, "rules": ["RULE-SET,missing,P", "SUB-RULE,(NETWORK,TCP),nope", "MATCH,P"]})
        self.assertIn("规则 'RULE-SET,missing,P' 引用了不存在的规则集: 'missing'", errors)
        self.assertIn("规则 'SUB-RULE,(NETWORK,TCP),nope' 引用了不存在的子规则: 'nope'", errors)

    def test_nameserver_policy_keeps_prefixed_keys_and_urls(self):
        """geosite:cn、rule-set:x 这类键带冒号，值可能是 https 地址，都不能拆错。"""
        from config_builder import _parse_nameserver_policy

        policy = _parse_nameserver_policy(
            "geosite:cn: 223.5.5.5\n"
            "rule-set:my-list: https://dns.alidns.com/dns-query\n"
            "+.example.com: 119.29.29.29\n"
            "geosite:gfw:8.8.8.8\n"
            "plain.com:1.1.1.1\n"
            "无效行\n"
        )
        self.assertEqual(
            {
                "geosite:cn": "223.5.5.5",
                "rule-set:my-list": "https://dns.alidns.com/dns-query",
                "+.example.com": "119.29.29.29",
                "geosite:gfw": "8.8.8.8",
                "plain.com": "1.1.1.1",
            },
            policy,
        )

    def test_draft_rejects_builtin_ruleset_alias_and_bad_overrides(self):
        """自定义规则集不能和内置规则集重名；目标覆盖必须是字符串映射，旧组名会被迁移。"""
        from fastapi import HTTPException

        from draft_service import _normalize_draft

        base = {"proxies": [], "custom_rules": ["DOMAIN,a.com,Steam"], "global_config": {}}
        for alias in ("cn", "discord", "google"):
            with self.assertRaises(HTTPException) as context:
                _normalize_draft({**base, "custom_rule_providers": {alias: {"type": "http", "url": "https://example.com/a.yaml"}}})
            self.assertEqual(400, context.exception.status_code, alias)

        with self.assertRaises(HTTPException):
            _normalize_draft({**base, "global_config": {"dustinwin_provider_targets": "netflix=Proxy"}})

        draft, _meta = _normalize_draft({
            **base,
            "custom_rule_providers": {"my-list": {"type": "http", "url": "https://example.com/a.yaml", "target": "Steam"}},
            "global_config": {"dustinwin_provider_targets": {"games": "Steam"}},
        })
        self.assertEqual(["DOMAIN,a.com,Game"], draft["custom_rules"])
        self.assertEqual("Game", draft["custom_rule_providers"]["my-list"]["target"])
        self.assertEqual({"games": "Game"}, draft["global_config"]["dustinwin_provider_targets"])

    def test_saved_private_ruleset_superseded_by_builtin_is_dropped(self):
        """内置之前上传的同名私有规则集（game-download）：旧草稿保存时自动移除并提示，新上传仍拒绝。"""
        from fastapi import HTTPException

        from draft_service import _normalize_draft

        legacy = {"type": "http", "behavior": "domain", "url": "https://example.com/g.yaml", "target": "DIRECT"}
        keep = {"type": "http", "behavior": "domain", "url": "https://example.com/n.yaml", "target": "Proxy"}
        saved = {"custom_rule_providers": {"game-download": legacy, "nbc": keep}}
        body = {"proxies": [], "global_config": {}, "custom_rule_providers": {"game-download": legacy, "nbc": keep}}

        draft, meta = _normalize_draft(body, saved)
        self.assertEqual(["nbc"], list(draft["custom_rule_providers"]))
        self.assertTrue(any("game-download" in warning for warning in meta["warnings"]))

        with self.assertRaises(HTTPException) as context:
            _normalize_draft(body, {"custom_rule_providers": {"nbc": keep}})
        self.assertEqual(400, context.exception.status_code)

        # “无基础规则”模式不生成内置规则集，旧的同名私有规则集必须保留，否则规则引用会断。
        none_body = {**body, "selected_rule_type": "none", "custom_rules": ["RULE-SET,game-download,Proxy"]}
        draft, meta = _normalize_draft(none_body, saved)
        self.assertEqual(["game-download", "nbc"], sorted(draft["custom_rule_providers"]))
        self.assertFalse(any("game-download" in warning for warning in meta["warnings"]))
        rules, providers = build_rules("none", draft["custom_rules"], draft["custom_rule_providers"])
        self.assertIn("RULE-SET,game-download,Proxy", rules)
        self.assertEqual("https://example.com/g.yaml", providers["game-download"]["url"])

        with self.assertRaises(HTTPException):
            _normalize_draft({**body, "custom_rule_providers": {"game-download": "bad"}}, saved)

    def test_media_policy_groups_default_to_aggregate_selectors(self):
        """独立流媒体策略组默认回落到对应的聚合组（Global TV / Asian TV / CN Mainland TV）。"""
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
        self.assertEqual("Proxy", groups["Game"]["proxies"][0])
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


def _domain_payload_matches(payload: list[str], host: str) -> bool:
    """按 mihomo domain 规则集语义匹配：+.x 匹配 x 及子域，.x 只匹配子域，*.x 匹配一级子域，其余精确匹配。"""
    host = host.lower().rstrip(".")
    for entry in payload:
        entry = entry.lower()
        if entry.startswith("+."):
            base = entry[2:]
            if host == base or host.endswith("." + base):
                return True
        elif entry.startswith("."):
            if host.endswith(entry):
                return True
        elif entry.startswith("*."):
            base = entry[2:]
            if host.endswith("." + base) and "." not in host[: -len(base) - 1]:
                return True
        elif host == entry:
            return True
    return False


class GameDownloadRulesetTest(unittest.TestCase):
    """内置 game-download：游戏下载 CDN 一律直连。"""

    PUBLIC_CDN_SUFFIXES = (
        "gcdn.co", "fastly.net", "akamai.net", "akamaized.net", "akamaihd.net",
        "cloudfront.net", "edgesuite.net", "edgekey.net", "llnwd.net", "fastly-edge.com", "akadns.net",
    )

    @classmethod
    def setUpClass(cls):
        from config_builder import BUILTIN_RULESET_DIR

        path = BUILTIN_RULESET_DIR / DUSTINWIN_PROVIDERS_MAP["game-download"]["file"]
        cls.payload = yaml.safe_load(path.read_text(encoding="utf-8"))["payload"]

    def test_payload_is_clean_domain_list(self):
        self.assertEqual(len(self.payload), len(set(self.payload)), "名单有重复条目")
        for entry in self.payload:
            self.assertIsInstance(entry, str)
            self.assertEqual(entry, entry.strip().lower(), entry)
            self.assertNotIn(",", entry)
            self.assertFalse(entry.startswith("*."), f"{entry} 应写成 +. 形式")

    def test_payload_never_releases_whole_public_cdn_suffix(self):
        for entry in self.payload:
            if not entry.startswith("+."):
                continue
            base = entry[2:]
            self.assertNotIn(base, self.PUBLIC_CDN_SUFFIXES, entry)
            # +.x.公共CDN 后缀时，x 必须带厂商标识（至少两段），例如 xboxlive.com.edgesuite.net。
            for suffix in self.PUBLIC_CDN_SUFFIXES:
                if base.endswith("." + suffix):
                    vendor_part = base[: -len(suffix) - 1]
                    self.assertGreaterEqual(vendor_part.count("."), 1, entry)

    def test_rule_is_placed_before_broad_lists_and_after_specific_ones(self):
        rules, providers = build_rules("dustinwin规则", [], {})
        names = [rule.split(",")[1] for rule in rules if rule.startswith("RULE-SET,")]
        index = names.index("game-download")
        self.assertIn("RULE-SET,game-download,DIRECT", rules)
        for broad in ("microsoft-cn", "games-cn", "games", "media", "tld-proxy", "gfw", "proxy", "cn"):
            self.assertLess(index, names.index(broad), broad)
        for specific in ("private", "ai", "ads"):
            self.assertGreater(index, names.index(specific), specific)
        provider = providers["game-download"]
        self.assertEqual(("domain", "yaml"), (provider["behavior"], provider["format"]))
        self.assertEqual("./ruleset/dustinwin/game-download.yaml", provider["path"])
        self.assertEqual(86400, provider["interval"])

    def test_observed_xbox_download_hosts_match(self):
        for host in (
            "cl-glcb907925.gcdn.co",
            "fg.microsoft.map.fastly.net",
            "assets1.xboxlive.com.edgesuite.net",
            "5.xb.delivery.microsoft.com",
            "assets1.xboxlive.com",
            "dlassets.xboxlive.com",
            "assets1.xboxlive.cn",
            "tlu.dl.delivery.mp.microsoft.com",
            "gs2.ww.prod.dl.playstation.net",
            "atum.hac.lp1.d4c.nintendo.net",
            "cache1-hkg1.steamcontent.com",
            "download.epicgames.com",
            "level3.blizzard.com",
            "uplaypc-s-ubisoft.cdn.ubi.com",
        ):
            self.assertTrue(_domain_payload_matches(self.payload, host), host)

    def test_ordinary_overseas_sites_are_not_released(self):
        for host in (
            "www.google.com",
            "www.youtube.com",
            "www.reddit.com",
            "github.githubassets.com",
            "www.nytimes.com",
            "nytimes.map.fastly.net",
            "reddit.map.fastly.net",
            "foo.global.ssl.fastly.net",
            "a248.e.akamai.net",
            "www.apple.com.edgekey.net",
            "twimg.edgesuite.net",
            "steamcommunity-a.akamaihd.net",
            "d1234abcd.cloudfront.net",
            "cl-glcb000000.gcdn.co",
            "xboxlive.com",
            "login.live.com",
            "www.xbox.com",
            "store.steampowered.com",
            "www.epicgames.com",
        ):
            self.assertFalse(_domain_payload_matches(self.payload, host), host)

    def test_legacy_private_ruleset_with_builtin_name_is_dropped(self):
        providers = {
            "game-download": {
                "type": "http", "behavior": "domain", "format": "yaml", "target": "DIRECT",
                "path": "./ruleset/users/4/game-download--old.yaml", "url": "https://example.com/x.yaml",
                "order": "优先 (覆盖)",
            }
        }
        rules, rule_providers = build_rules("dustinwin规则", [], providers)
        self.assertEqual(1, sum(rule.startswith("RULE-SET,game-download,") for rule in rules))
        self.assertEqual("./ruleset/dustinwin/game-download.yaml", rule_providers["game-download"]["path"])

    def test_ruleset_route_serves_bundled_file(self):
        import ruleset_updater

        path = ruleset_updater.get_ruleset_cache_path("game-download.yaml")
        self.assertTrue(path.is_file(), path)
        self.assertNotEqual(ruleset_updater.RULESET_CACHE_DIR, path.parent)


class DualProtocolFallbackTest(unittest.TestCase):
    """双协议回落：同一 VPS 的 UDP 与 TCP 节点合成 fallback 组，可选优先协议。"""

    PROXIES = [
        {"name": "Ali-1/HK-HY2", "type": "hysteria2", "server": "1.1.1.1", "port": 443, "password": "p"},
        {"name": "Hw/SG", "type": "anytls", "server": "2.2.2.2", "port": 443, "password": "p"},
        {"name": "Ali-1/HK-AnyTLS", "type": "anytls", "server": "1.1.1.1", "port": 8443, "password": "p"},
        {"name": "Dedi-TUIC", "type": "tuic", "server": "Dedi.example.com", "port": 443, "uuid": "u", "password": "p"},
        {"name": "Dedi-VLESS", "type": "vless", "server": "dedi.example.com", "port": 443, "uuid": "u"},
        {"name": "Solo-HY2-a", "type": "hysteria2", "server": "3.3.3.3", "port": 443, "password": "p"},
        {"name": "Solo-HY2-b", "type": "hysteria2", "server": "3.3.3.3", "port": 444, "password": "p"},
    ]

    def build(self, **global_config):
        return build_config(self.PROXIES, global_config)

    @staticmethod
    def groups(config):
        return {group["name"]: group for group in config["proxy-groups"]}

    def test_disabled_keeps_flat_groups(self):
        config = self.build()
        groups = self.groups(config)
        # 普通模式下常用分组紧跟 Proxy。
        self.assertEqual(["Auto - UrlTest", "Proxy", "AI Suite", "Global TV", "Domestic"], list(groups)[:5])
        self.assertEqual([p["name"] for p in self.PROXIES], groups["Auto - UrlTest"]["proxies"])
        self.assertFalse(any(group["type"] == "fallback" for group in config["proxy-groups"]))

    def test_udp_first_pairs_by_server_and_orders_members(self):
        config = self.build(dual_protocol_fallback=True, dual_protocol_priority="udp")
        groups = self.groups(config)
        self.assertEqual(["Ali-1/HK-HY2", "Ali-1/HK-AnyTLS"], groups["Ali-1/HK"]["proxies"])
        # server 比较不区分大小写；组名取节点名的公共前缀。
        self.assertEqual(["Dedi-TUIC", "Dedi-VLESS"], groups["Dedi"]["proxies"])
        fallback = groups["Ali-1/HK"]
        self.assertEqual("fallback", fallback["type"])
        self.assertFalse(fallback["lazy"])
        self.assertEqual(2000, fallback["timeout"])
        self.assertEqual(groups["Auto - UrlTest"]["url"], fallback["url"])
        # 回落组在面板分组列表中隐藏，但仍是 Proxy 等分组的成员。
        self.assertIs(True, fallback["hidden"])
        # 同一 server 只有 UDP 节点时不配对。
        self.assertNotIn("3.3.3.3", groups)
        self.assertEqual(
            ["Ali-1/HK", "Hw/SG", "Dedi", "Solo-HY2-a", "Solo-HY2-b"],
            groups["Auto - UrlTest"]["proxies"],
        )
        # Proxy 每台 VPS 只出现一次，已配对的原始节点收进「单协议节点」子分组。
        self.assertEqual(
            ["Auto - UrlTest", "DIRECT", "Ali-1/HK", "Hw/SG", "Dedi", "Solo-HY2-a", "Solo-HY2-b", "单协议节点"],
            groups["Proxy"]["proxies"],
        )
        single = groups["单协议节点"]
        self.assertEqual("select", single["type"])
        self.assertNotIn("hidden", single)
        self.assertEqual(["Ali-1/HK-HY2", "Ali-1/HK-AnyTLS", "Dedi-TUIC", "Dedi-VLESS"], single["proxies"])
        names = [group["name"] for group in config["proxy-groups"]]
        # 常用分组紧跟在「单协议节点」之后。
        self.assertEqual(["Auto - UrlTest", "Proxy", "单协议节点", "AI Suite", "Global TV", "Domestic"], names[:6])
        # 所有列出节点的分组都只列合并后的成员，外加「单协议节点」入口，不平铺已配对的原始节点。
        auto_members = groups["Auto - UrlTest"]["proxies"]
        self.assertNotIn("单协议节点", auto_members)
        paired = {"Ali-1/HK-HY2", "Ali-1/HK-AnyTLS", "Dedi-TUIC", "Dedi-VLESS", "单协议节点"}
        checked = []
        for name, group in groups.items():
            if name == "Proxy" or group["type"] != "select" or "Ali-1/HK" not in group["proxies"]:
                continue
            checked.append(name)
            members = [item for item in group["proxies"] if item in set(auto_members) | paired]
            self.assertEqual(auto_members + ["单协议节点"], members, name)
        for name in ["Netflix", "AI Suite", "Microsoft", "Youtube", "Global TV", "Asian TV", "Game"]:
            self.assertIn(name, checked)
        # 既有策略组顺序不变：只在 Proxy 后插入子分组，回落组追加在最后。
        flat_names = [group["name"] for group in self.build()["proxy-groups"]]
        self.assertEqual(flat_names, [name for name in names if name != "单协议节点"][: len(flat_names)])
        errors, _warnings = validate_config(config)
        self.assertEqual([], errors)

    def test_tcp_first_reverses_member_order(self):
        groups = self.groups(self.build(dual_protocol_fallback=True, dual_protocol_priority="tcp"))
        self.assertEqual(["Ali-1/HK-AnyTLS", "Ali-1/HK-HY2"], groups["Ali-1/HK"]["proxies"])
        self.assertEqual(["Dedi-VLESS", "Dedi-TUIC"], groups["Dedi"]["proxies"])

    def test_invalid_priority_falls_back_to_udp(self):
        groups = self.groups(self.build(dual_protocol_fallback=True, dual_protocol_priority="weird"))
        self.assertEqual(["Ali-1/HK-HY2", "Ali-1/HK-AnyTLS"], groups["Ali-1/HK"]["proxies"])

    def test_group_name_never_collides_with_nodes_or_builtin_groups(self):
        proxies = [
            {"name": "Netflix", "type": "hysteria2", "server": "9.9.9.9", "port": 443, "password": "p"},
            {"name": "Netflix-AnyTLS", "type": "anytls", "server": "9.9.9.9", "port": 443, "password": "p"},
            {"name": "Edge", "type": "hysteria2", "server": "8.8.8.8", "port": 443, "password": "p"},
            {"name": "Edge AnyTLS", "type": "anytls", "server": "8.8.8.8", "port": 443, "password": "p"},
            {"name": "Tokyo", "type": "hysteria2", "server": "7.7.7.7", "port": 443, "password": "p"},
            {"name": "JP backup", "type": "anytls", "server": "7.7.7.7", "port": 443, "password": "p"},
        ]
        config = build_config(proxies, {"dual_protocol_fallback": True})
        names = [group["name"] for group in config["proxy-groups"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("Netflix 双协议", names)
        self.assertIn("Edge 双协议", names)
        # 节点名没有公共前缀时用 server 地址命名。
        self.assertIn("7.7.7.7", names)
        self.assertEqual([], validate_config(config)[0])

    def test_group_name_cuts_shared_prefix_only_at_separators(self):
        from clash_meta_gen import _vps_group_base_name

        self.assertEqual("Test", _vps_group_base_name(["Test-HY2", "Test-HTTP"], "1.1.1.1"))
        self.assertEqual("Ali-1/HK", _vps_group_base_name(["Ali-1/HK-HY2", "Ali-1/HK-AnyTLS"], "1.1.1.1"))
        self.assertEqual("Edge", _vps_group_base_name(["Edge", "Edge AnyTLS"], "1.1.1.1"))
        self.assertEqual("1.1.1.1", _vps_group_base_name(["HY2", "HTTP"], "1.1.1.1"))
        self.assertEqual("1.1.1.1", _vps_group_base_name(["Tokyo", "JP backup"], "1.1.1.1"))
        self.assertEqual("香港", _vps_group_base_name(["香港HY2", "香港AnyTLS"], "1.1.1.1"))
        self.assertEqual("【HK】", _vps_group_base_name(["【HK】HY2", "【HK】AnyTLS"], "1.1.1.1"))
        self.assertEqual("日本", _vps_group_base_name(["日本｜HY2", "日本｜AnyTLS"], "1.1.1.1"))

    def test_repeated_name_collisions_and_ipv6_brackets(self):
        proxies = [
            {"name": "HK 双协议", "type": "anytls", "server": "9.9.9.9", "port": 443, "password": "p"},
            {"name": "HK", "type": "anytls", "server": "8.8.8.8", "port": 443, "password": "p"},
            {"name": "HK-HY2", "type": "hysteria2", "server": "[2001:db8::1]", "port": 443, "password": "p"},
            {"name": "HK-AnyTLS", "type": "anytls", "server": "2001:DB8::1", "port": 443, "password": "p"},
            {"name": "HK-B-HY2", "type": "hysteria2", "server": "1.1.1.1", "port": 443, "password": "p"},
            {"name": "HK-B-AnyTLS", "type": "anytls", "server": "1.1.1.1", "port": 443, "password": "p"},
        ]
        config = build_config(proxies, {"dual_protocol_fallback": True})
        names = [group["name"] for group in config["proxy-groups"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("HK 双协议 2", names)
        self.assertEqual([], validate_config(config)[0])

    def test_single_protocol_group_name_avoids_node_names_and_is_skipped_without_pairs(self):
        proxies = [
            {"name": "单协议节点", "type": "anytls", "server": "9.9.9.9", "port": 443, "password": "p"},
            {"name": "A-HY2", "type": "hysteria2", "server": "1.1.1.1", "port": 443, "password": "p"},
            {"name": "A-AnyTLS", "type": "anytls", "server": "1.1.1.1", "port": 443, "password": "p"},
        ]
        groups = self.groups(build_config(proxies, {"dual_protocol_fallback": True}))
        self.assertEqual(["A-HY2", "A-AnyTLS"], groups["单协议节点 2"]["proxies"])
        self.assertEqual("单协议节点 2", groups["Proxy"]["proxies"][-1])
        # 没有任何配对时不生成子分组，Proxy 与普通模式一致。
        solo = [proxies[0], {"name": "B", "type": "hysteria2", "server": "2.2.2.2", "port": 443, "password": "p"}]
        config = build_config(solo, {"dual_protocol_fallback": True})
        self.assertEqual(
            [group["name"] for group in build_config(solo, {})["proxy-groups"]],
            [group["name"] for group in config["proxy-groups"]],
        )

    def test_draft_normalizes_priority_case(self):
        from draft_service import _normalize_draft

        draft, _meta = _normalize_draft({"proxies": [], "global_config": {"dual_protocol_priority": " TCP "}})
        self.assertEqual("tcp", draft["global_config"]["dual_protocol_priority"])
        draft, _meta = _normalize_draft({"proxies": [], "global_config": {"dual_protocol_priority": None}})
        self.assertEqual("udp", draft["global_config"]["dual_protocol_priority"])

    def test_minimal_profile_supports_dual_protocol(self):
        config = self.build(generation_profile="minimal", dual_protocol_fallback=True, dual_protocol_priority="tcp")
        groups = self.groups(config)
        self.assertEqual(["Auto - UrlTest", "Proxy", "单协议节点", "Ali-1/HK", "Dedi"], list(groups))
        self.assertEqual("单协议节点", groups["Proxy"]["proxies"][-1])
        self.assertEqual(["Ali-1/HK-AnyTLS", "Ali-1/HK-HY2"], groups["Ali-1/HK"]["proxies"])

    def test_draft_validates_dual_protocol_settings(self):
        from fastapi import HTTPException

        from config_defaults import build_global_config_schema
        from draft_service import _normalize_draft

        draft, _meta = _normalize_draft({"proxies": [], "global_config": {}})
        self.assertIs(False, draft["global_config"]["dual_protocol_fallback"])
        self.assertEqual("udp", draft["global_config"]["dual_protocol_priority"])
        for bad in ({"dual_protocol_priority": "quic"}, {"dual_protocol_fallback": "yes"}):
            with self.assertRaises(HTTPException) as context:
                _normalize_draft({"proxies": [], "global_config": bad})
            self.assertEqual(400, context.exception.status_code)

        schema = build_global_config_schema()
        self.assertEqual("checkbox", schema["dual_protocol_fallback"]["type"])
        self.assertEqual({"key": "dual_protocol_fallback", "equals": True}, schema["dual_protocol_priority"]["visible"])
        self.assertEqual(["udp", "tcp"], [option[0] for option in schema["dual_protocol_priority"]["options"]])


class DialerProxyValidationTest(unittest.TestCase):
    """链式代理上游改名或删除后，结构校验要给出明确提示，而不是只有 mihomo 的 not found。"""

    def config(self, dialer, **global_config):
        proxies = [
            {"name": "Ali3-HY2", "type": "hysteria2", "server": "3.3.3.3", "port": 443, "password": "p"},
            {"name": "Ali3-AnyTLS", "type": "anytls", "server": "3.3.3.3", "port": 443, "password": "p"},
            {"name": "Yuusei", "type": "ss", "server": "4.4.4.4", "port": 8388, "cipher": "aes-128-gcm",
             "password": "p", "dialer-proxy": dialer},
        ]
        return build_config(proxies, global_config)

    def test_missing_upstream_is_reported_clearly(self):
        errors, _warnings = validate_config(self.config("Ali-3/HK"))
        self.assertTrue(any("Yuusei" in error and "Ali-3/HK" in error and "dialer-proxy" in error for error in errors), errors)

    def test_self_reference_is_rejected(self):
        errors, _warnings = validate_config(self.config("Yuusei"))
        self.assertTrue(any("不能指向自己" in error for error in errors), errors)

    def test_existing_node_or_fallback_group_is_valid_upstream(self):
        self.assertEqual([], validate_config(self.config("Ali3-HY2"))[0])
        self.assertEqual([], validate_config(self.config("Ali3", dual_protocol_fallback=True))[0])


if __name__ == "__main__":
    unittest.main()
