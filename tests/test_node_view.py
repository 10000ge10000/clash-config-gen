import copy
import unittest

from ui.node_view import _merge_internal_metadata, _parse_single_node_yaml


class NodeViewEditTest(unittest.TestCase):
    def test_edit_parser_uses_shared_importer_and_preserves_extended_fields(self):
        parsed = _parse_single_node_yaml(
            """- name: edited
  type: ss
  server: edited.example.com
  port: 9443
  cipher: aes-128-gcm
  password: password
  udp: true
  x-advanced:
    nested: true
"""
        )
        self.assertEqual("edited", parsed["name"])
        self.assertEqual(9443, parsed["port"])
        self.assertEqual({"nested": True}, parsed["x-advanced"])

    def test_invalid_port_is_rejected_before_editor_state_can_change(self):
        original = {
            "name": "kept",
            "type": "ss",
            "server": "kept.example.com",
            "port": 9443,
            "cipher": "aes-128-gcm",
            "password": "password",
            "_source_id": "source-1",
        }
        before = copy.deepcopy(original)
        for value in ("true", "false", "443.0", "443.5"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    _parse_single_node_yaml(
                        f"""- name: changed
  type: ss
  server: changed.example.com
  port: {value}
  cipher: aes-128-gcm
  password: password
"""
                    )
                self.assertEqual(before, original)

    def test_editor_requires_exactly_one_node(self):
        with self.assertRaisesRegex(ValueError, "1 个节点"):
            _parse_single_node_yaml(
                """proxies:
  - name: one
    type: ss
    server: one.example.com
    port: 443
    cipher: aes-128-gcm
    password: password
  - name: two
    type: ss
    server: two.example.com
    port: 8443
    cipher: aes-128-gcm
    password: password
"""
            )

    def test_editor_restores_internal_source_metadata_after_parse(self):
        parsed = {"name": "edited", "type": "ss", "server": "edited.example.com", "port": 443}
        original = {"_source_id": "source-1", "_source_name": "Imported", "secret": "not-internal"}
        merged = _merge_internal_metadata(parsed, original)
        self.assertEqual("source-1", merged["_source_id"])
        self.assertEqual("Imported", merged["_source_name"])
        self.assertNotIn("secret", merged)
