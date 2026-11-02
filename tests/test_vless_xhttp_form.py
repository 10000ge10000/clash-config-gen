import unittest

from node_builder import NODE_FORM_SCHEMA, build_manual_node


def _walk(value):
    if isinstance(value, dict):
        if "key" in value:
            yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


class VlessXhttpFormTest(unittest.TestCase):
    def fields(self, **extra):
        base = {
            "node_name": "x",
            "node_server": "203.0.113.7",
            "node_port": 9531,
            "node_uuid": "11111111-2222-3333-4444-555555555555",
            "vless_tls": True,
            "vless_flow": "none",
            "vless_network": "xhttp",
            "vless_servername": "www.apple.com",
            "vless_public_key": "bOo0bIOnHkkxQJkJ8SVtAQ1jRC3B9sXKmHm_vQ9k7hI",
            "vless_short_id": "0011",
        }
        base.update(extra)
        return base

    def test_builds_xhttp_with_encryption(self):
        node = build_manual_node("vless", self.fields(
            vless_xhttp_path="/abc", vless_xhttp_mode="packet-up",
            vless_encryption="mlkem768x25519plus.native.0rtt.abc", vless_alpn="h2",
        ))
        self.assertEqual({"path": "/abc", "mode": "packet-up"}, node["xhttp-opts"])
        self.assertEqual("mlkem768x25519plus.native.0rtt.abc", node["encryption"])
        self.assertEqual(["h2"], node["alpn"])
        self.assertNotIn("flow", node)
        self.assertEqual("0011", node["reality-opts"]["short-id"])

    def test_empty_encryption_is_omitted(self):
        node = build_manual_node("vless", self.fields(vless_encryption="none"))
        self.assertNotIn("encryption", node)

    def test_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            build_manual_node("vless", self.fields(vless_xhttp_mode="nope"))

    def test_reality_fields_do_not_depend_on_flow(self):
        fields = {item["key"]: item for item in _walk(NODE_FORM_SCHEMA)}
        for key in ("vless_public_key", "vless_short_id"):
            self.assertFalse(fields[key].get("visible"), key)
        for key in ("vless_xhttp_path", "vless_xhttp_host", "vless_xhttp_mode"):
            self.assertEqual("xhttp", fields[key]["visible"]["equals"])


if __name__ == "__main__":
    unittest.main()
