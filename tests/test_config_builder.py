import unittest

import yaml

from config_builder import build_config, build_yaml, validate_config
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
        self.assertIn("规则 'MATCH,Proxy' 指向了不存在的策略组: 'Proxy'", warnings)

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

        self.assertEqual([], errors)
        self.assertIn("规则 'GEOIP,CN,Domestic,no-resolve' 指向了不存在的策略组: 'Domestic'", warnings)

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

        self.assertTrue(rendered.startswith("# Generator: Clash-Config-Gen\n"))
        self.assertIn("# Project: 一万AI分享 Clash/OpenClash 订阅生成器", rendered)
        self.assertIn("# Usage: 可直接导入 OpenClash、Clash Verge、FlClash 或 mihomo 兼容客户端", rendered)
        self.assertEqual(config, loaded)


if __name__ == "__main__":
    unittest.main()
