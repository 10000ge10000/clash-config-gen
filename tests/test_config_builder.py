import unittest

from config_builder import validate_config


class ValidateConfigTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
