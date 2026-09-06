import os
import sys
from pathlib import Path
from typing import Any
import unittest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from normalizer import normalize_proxy, normalize_proxies, normalize_proxy_for_mihomo
from node_builder import build_manual_node
import importers


class NormalizerDefensiveSanitizationTest(unittest.TestCase):
    def test_vision_flow_with_smux_enabled_is_sanitized_with_warning(self):
        proxy: dict[str, Any] = {
            "name": "vless-reality-test",
            "type": "vless",
            "server": "1.2.3.4",
            "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "flow": "xtls-rprx-vision",
            "tls": True,
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
        res = normalize_proxy(proxy)
        self.assertNotIn("smux", res.proxy)
        self.assertEqual(res.proxy["flow"], "xtls-rprx-vision")
        self.assertEqual(res.proxy["server"], "1.2.3.4")
        self.assertIn("已自动移除与 xtls-rprx-vision 互斥的 smux 多路复用配置", res.warnings)

    def test_vision_udp443_flow_with_smux_is_also_sanitized(self):
        proxy: dict[str, Any] = {
            "name": "vless-vision-udp443",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "flow": "xtls-rprx-vision-udp443",
            "smux": {
                "enabled": True,
                "protocol": "yamux",
            },
        }
        res = normalize_proxy(proxy)
        self.assertNotIn("smux", res.proxy)
        self.assertIn("已自动移除与 xtls-rprx-vision 互斥的 smux 多路复用配置", res.warnings)

    def test_vision_flow_with_smux_boolean_or_truthy_string_sanitized(self):
        for smux_spec in (True, {"enabled": "true"}, {"enabled": 1}, {"enabled": "yes"}):
            with self.subTest(smux_spec=smux_spec):
                proxy: dict[str, Any] = {
                    "name": "vless-smux-truthy",
                    "type": "vless",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "flow": "xtls-rprx-vision",
                    "smux": smux_spec,
                }
                res = normalize_proxy(proxy)
                self.assertNotIn("smux", res.proxy)
                self.assertIn("已自动移除与 xtls-rprx-vision 互斥的 smux 多路复用配置", res.warnings)

    def test_vision_flow_with_smux_disabled_is_retained_without_warning(self):
        proxy: dict[str, Any] = {
            "name": "vless-smux-disabled",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "flow": "xtls-rprx-vision",
            "smux": {
                "enabled": False,
                "protocol": "h2mux",
            },
        }
        res = normalize_proxy(proxy)
        self.assertIn("smux", res.proxy)
        self.assertFalse(res.proxy["smux"]["enabled"])
        self.assertNotIn("已自动移除与 xtls-rprx-vision 互斥的 smux 多路复用配置", res.warnings)

    def test_non_vision_flow_keeps_smux(self):
        vmess_proxy: dict[str, Any] = {
            "name": "vmess-ws",
            "type": "vmess",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "alterId": 0,
            "cipher": "auto",
            "smux": {
                "enabled": True,
                "protocol": "h2mux",
            },
        }
        res = normalize_proxy(vmess_proxy)
        self.assertIn("smux", res.proxy)
        self.assertTrue(res.proxy["smux"]["enabled"])
        self.assertNotIn("已自动移除与 xtls-rprx-vision 互斥的 smux 多路复用配置", res.warnings)

    def test_batch_normalization_includes_node_name_in_warning(self):
        proxies = [
            {
                "name": "Node-Vision",
                "type": "vless",
                "server": "1.1.1.1",
                "port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "flow": "xtls-rprx-vision",
                "smux": {"enabled": True},
            },
            {
                "name": "Node-Normal",
                "type": "vmess",
                "server": "2.2.2.2",
                "port": 443,
                "uuid": "22222222-3333-4444-5555-666666666666",
                "alterId": 0,
                "cipher": "auto",
                "smux": {"enabled": True},
            },
        ]
        norm_proxies, warnings, _errors = normalize_proxies(proxies)
        self.assertNotIn("smux", norm_proxies[0])
        self.assertIn("smux", norm_proxies[1])
        self.assertTrue(any("Node-Vision: 已自动移除与 xtls-rprx-vision 互斥的 smux 多路复用配置" in w for w in warnings))

        # normalize_proxy_for_mihomo helper
        mihomo_node = normalize_proxy_for_mihomo(proxies[0])
        self.assertNotIn("smux", mihomo_node)

    def test_node_builder_mutual_exclusion_guard(self):
        # 1. flow contains xtls-rprx-vision and enable_smux=True -> raises ValueError
        with self.assertRaises(ValueError) as ctx:
            build_manual_node(
                "vless",
                {
                    "node_name": "vless-mutual-exclusion",
                    "node_server": "example.com",
                    "node_port": 443,
                    "node_uuid": "11111111-2222-3333-4444-555555555555",
                    "vless_flow": "xtls-rprx-vision",
                    "enable_smux": True,
                    "smux_enabled": True,
                },
            )
        self.assertIn("xtls-rprx-vision 与 smux 多路复用互斥，不可同时启用", str(ctx.exception))

        # 2. flow contains xtls-rprx-vision-udp443 and enable_smux=True -> raises ValueError
        with self.assertRaises(ValueError) as ctx:
            build_manual_node(
                "vless",
                {
                    "node_name": "vless-vision-udp443",
                    "node_server": "example.com",
                    "node_port": 443,
                    "node_uuid": "11111111-2222-3333-4444-555555555555",
                    "vless_flow": "xtls-rprx-vision-udp443",
                    "enable_smux": True,
                },
            )
        self.assertIn("xtls-rprx-vision 与 smux 多路复用互斥，不可同时启用", str(ctx.exception))

        # 2b. flow passed as 'flow' key directly instead of 'vless_flow' -> raises ValueError
        with self.assertRaises(ValueError) as ctx:
            build_manual_node(
                "vless",
                {
                    "node_name": "vless-vision-flow-alias",
                    "node_server": "example.com",
                    "node_port": 443,
                    "node_uuid": "11111111-2222-3333-4444-555555555555",
                    "flow": "xtls-rprx-vision",
                    "enable_smux": True,
                },
            )
        self.assertIn("xtls-rprx-vision 与 smux 多路复用互斥，不可同时启用", str(ctx.exception))

        # 3. flow is none and enable_smux=True -> succeeds
        node = build_manual_node(
            "vless",
            {
                "node_name": "vless-no-vision",
                "node_server": "example.com",
                "node_port": 443,
                "node_uuid": "11111111-2222-3333-4444-555555555555",
                "vless_flow": "none",
                "enable_smux": True,
            },
        )
        self.assertIn("smux", node)
        self.assertTrue(node["smux"]["enabled"])

        # 4. flow is vision and enable_smux=False -> succeeds
        node = build_manual_node(
            "vless",
            {
                "node_name": "vless-vision-smux-disabled",
                "node_server": "example.com",
                "node_port": 443,
                "node_uuid": "11111111-2222-3333-4444-555555555555",
                "vless_flow": "xtls-rprx-vision",
                "enable_smux": False,
            },
        )
        self.assertNotIn("smux", node)
        self.assertEqual("xtls-rprx-vision", node["flow"])

    def test_importer_sanitizes_vision_smux_yaml(self):
        raw_yaml = """proxies:
  - name: imported-vless-reality
    type: vless
    server: 198.51.100.1
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: example.com
    reality-opts:
      public-key: 1111111111111111111111111111111111111111111=
      short-id: 01234567
    client-fingerprint: chrome
    smux:
      enabled: true
      protocol: h2mux
      brutal-opts:
        enabled: true
        up: 100 Mbps
        down: 100 Mbps
"""
        nodes, warnings = importers.parse_proxy_yaml(raw_yaml)
        self.assertEqual(1, len(nodes))
        self.assertNotIn("smux", nodes[0])
        self.assertEqual("xtls-rprx-vision", nodes[0]["flow"])
        self.assertTrue(any("已自动移除与 xtls-rprx-vision 互斥的 smux 多路复用配置" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
