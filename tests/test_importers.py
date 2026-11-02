import unittest
import socket as system_socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import importers
from normalizer import parse_strict_port
import requests


class ImportSecurityTest(unittest.TestCase):
    def test_parse_strict_port_accepts_only_unsigned_decimal_integers(self):
        self.assertEqual(443, parse_strict_port(443))
        self.assertEqual(443, parse_strict_port("0443"))
        for value in (True, False, 443.0, 443.5, "", " 443", "+443", "-443", "443.0", "4e2", 0, 65536):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_strict_port(value)

    def test_parse_proxy_yaml_rejects_invalid_port_instead_of_skipping_node(self):
        for value in ("true", "false", "443.0", "443.5"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    importers.parse_proxy_yaml(
                        f"""proxies:
  - name: invalid-port
    type: ss
    server: example.com
    port: {value}
    cipher: aes-128-gcm
    password: password
"""
                    )

    def test_external_url_rejects_private_address(self):
        with patch(
            "importers.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("127.0.0.1", 0))],
        ):
            with self.assertRaises(ValueError):
                importers.validate_external_url("http://example.test/sub")

    def test_external_url_accepts_public_address(self):
        with patch(
            "importers.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("93.184.216.34", 0))],
        ):
            self.assertEqual(
                "https://example.test/sub?format=yaml",
                importers.validate_external_url("https://example.test/sub?format=yaml"),
            )

    def test_fetch_rejects_redirect_and_closes_response(self):
        response = Mock(status_code=302)
        response.headers = {"location": "http://example.test/private"}
        with patch(
            "importers._resolve_public_external_url",
            side_effect=[
                ("https://example.test/sub", ("93.184.216.34",)),
                ValueError("URL 解析到内网、本机或保留地址，已拒绝服务端访问"),
            ],
        ):
            with patch("importers.requests.Session.get", return_value=response):
                with self.assertRaises(ValueError):
                    importers.fetch_text_from_external_url("https://example.test/sub")
        response.close.assert_called_once_with()

    def test_fetch_closes_response_when_size_limit_is_exceeded(self):
        response = Mock(status_code=200)
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"
        response.iter_content.return_value = [b"x" * (importers.MAX_REMOTE_SUBSCRIPTION_BYTES + 1)]
        with patch(
            "importers._resolve_public_external_url",
            return_value=("https://example.test/sub", ("93.184.216.34",)),
        ):
            with patch("importers.requests.Session.get", return_value=response):
                with self.assertRaises(ValueError):
                    importers.fetch_text_from_external_url("https://example.test/sub")
        response.close.assert_called_once_with()

    def test_fetch_uses_verified_ip_when_dns_would_rebind_to_private_address(self):
        targets = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.host_header = self.headers.get("Host")
                body = b"proxies:\n  - name: pinned\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/yaml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        try:
            port = server.server_address[1]
            import threading

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def fake_connect(address, *args, **kwargs):
                targets.append(address)
                sock = system_socket.socket(system_socket.AF_INET, system_socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect(("127.0.0.1", port))
                return sock

            public = (system_socket.AF_INET, system_socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
            private = (system_socket.AF_INET, system_socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
            with patch("importers.socket.getaddrinfo", side_effect=[[public], [private]]) as resolve:
                with patch("importers.urllib3_connection.connection.create_connection", side_effect=fake_connect):
                    text, content_type = importers.fetch_text_from_external_url(
                        f"http://example.test:{port}/subscription"
                    )
            self.assertIn("pinned", text)
            self.assertIn("yaml", content_type)
            # The second private DNS answer was never requested because the
            # transport connected to the first validated address directly.
            self.assertEqual(1, resolve.call_count)
            self.assertEqual([("93.184.216.34", port)], targets)
            self.assertEqual(f"example.test:{port}", server.host_header)
        finally:
            server.shutdown()
            server.server_close()

    def test_redirect_is_revalidated_and_pinned_per_hop(self):
        targets = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"proxies:\n  - name: redirected\n"
                if self.path == "/first":
                    self.send_response(302)
                    self.send_header("Location", f"http://second.test:{self.server.server_address[1]}/final")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/yaml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        try:
            port = server.server_address[1]
            import threading

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def fake_connect(address, *args, **kwargs):
                targets.append(address)
                sock = system_socket.socket(system_socket.AF_INET, system_socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect(("127.0.0.1", port))
                return sock

            first = (system_socket.AF_INET, system_socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
            second = (system_socket.AF_INET, system_socket.SOCK_STREAM, 6, "", ("151.101.1.69", port))
            with patch("importers.socket.getaddrinfo", side_effect=[[first], [second]]) as resolve:
                with patch("importers.urllib3_connection.connection.create_connection", side_effect=fake_connect):
                    text, _content_type = importers.fetch_text_from_external_url(
                        f"http://first.test:{port}/first"
                    )
            self.assertIn("redirected", text)
            self.assertEqual(2, resolve.call_count)
            self.assertEqual([("93.184.216.34", port), ("151.101.1.69", port)], targets)
        finally:
            server.shutdown()
            server.server_close()

    def test_https_pin_keeps_original_host_for_sni_and_certificate(self):
        request = requests.Request("GET", "https://example.test/sub").prepare()
        adapter = importers._PinnedIPHTTPAdapter("example.test", "93.184.216.34")
        pool = adapter.get_connection_with_tls_context(request, verify=True, proxies={})
        connection = pool._new_conn()
        self.assertEqual("example.test", connection.server_hostname)
        self.assertEqual("example.test", connection.assert_hostname)
        self.assertEqual("example.test", request.headers.get("Host", "example.test"))

    def test_vless_xhttp_share_link_keeps_transport_and_encryption(self):
        proxy = importers.parse_share_link(
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:9531"
            "?encryption=mlkem768x25519plus.native.0rtt.a%2Bb%2Fc&security=reality&sni=www.apple.com"
            "&fp=chrome&pbk=PBK&sid=0011&type=xhttp&path=%2Fabc&mode=stream-one&alpn=h2#HK-vless-xhttp"
        )
        self.assertEqual("xhttp", proxy["network"])
        self.assertTrue(proxy["tls"])
        # + 和 / 经百分号编码后必须原样还原，否则客户端握手失败
        self.assertEqual("mlkem768x25519plus.native.0rtt.a+b/c", proxy["encryption"])
        self.assertEqual({"path": "/abc", "mode": "stream-one"}, proxy["xhttp-opts"])
        self.assertEqual(["h2"], proxy["alpn"])
        self.assertEqual({"public-key": "PBK", "short-id": "0011"}, proxy["reality-opts"])

    def test_vless_share_link_encryption_none_is_not_kept(self):
        proxy = importers.parse_share_link(
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443?encryption=none&security=reality&type=tcp#a"
        )
        self.assertEqual("tcp", proxy["network"])
        self.assertNotIn("encryption", proxy)
        self.assertNotIn("xhttp-opts", proxy)

    def test_share_link_fragment_is_node_name(self):
        links = {
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:9527?security=reality&type=tcp#HK-vless-reality": "HK-vless-reality",
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:9531?security=reality&type=xhttp&path=%2Fa#HK%20vless-xhttp": "HK vless-xhttp",
            "hysteria2://pw@203.0.113.7:29949?sni=a.example#HK-hy2": "HK-hy2",
            "tuic://11111111-2222-3333-4444-555555555555:pw@203.0.113.7:9528?sni=a.example#HK-tuic": "HK-tuic",
            "anytls://pw@203.0.113.7:9530?sni=a.example#HK-anytls": "HK-anytls",
            "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206cHc=@203.0.113.7:9529#HK-ss": "HK-ss",
            "trojan://pw@203.0.113.7:443?sni=a.example#HK-trojan": "HK-trojan",
        }
        for link, expected in links.items():
            self.assertEqual(importers.parse_share_link(link)["name"], expected, link)
        # 没有 fragment 时仍用协议加地址，换行等控制字符不进节点名
        bare = "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:9527?security=reality"
        self.assertEqual(importers.parse_share_link(bare)["name"], "vless-203.0.113.7")
        self.assertEqual(importers.parse_share_link(bare + "#%20%20")["name"], "vless-203.0.113.7")
        self.assertEqual(importers.parse_share_link(bare + "#a%0Ab")["name"], "a b")

    def test_share_links_from_one_server_keep_both_vless_nodes(self):
        text = "\n".join([
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:9527?security=reality&type=tcp#HK-vless-reality",
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:9531?security=reality&type=xhttp&path=%2Fa#HK-vless-xhttp",
        ])
        proxies, _ = importers.parse_proxy_yaml(text)
        self.assertEqual([p["name"] for p in proxies], ["HK-vless-reality", "HK-vless-xhttp"])

    def test_terminal_copied_node_snippets_parse(self):
        indented = """  - name: "HK-ss"
    type: ss
    server: "203.0.113.7"
    port: 9529
    cipher: "2022-blake3-aes-128-gcm"
    password: "AAAAAAAAAAAAAAAAAAAAAA=="
  - name: "HK-vmess"
    type: vmess
    server: "203.0.113.7"
    port: 8880
    uuid: "11111111-2222-3333-4444-555555555555"
    cipher: auto
    alterId: 0
"""
        lost_first_indent = indented.lstrip()
        top_level = "\n".join(line[2:] for line in indented.splitlines())
        for label, text in (("indented", indented), ("lost-first-indent", lost_first_indent), ("top-level", top_level), ("surrounding-blanks", f"\n\n{indented}\n")):
            with self.subTest(label):
                nodes, _ = importers.parse_proxy_yaml(text)
                self.assertEqual(["HK-ss", "HK-vmess"], [node["name"] for node in nodes])

    def test_onekey_export_yaml_keeps_xhttp_fields(self):
        content = """# onekey-export schema=1 core=v1.19.33
proxies:
  - name: "HK-vless-xhttp"
    type: vless
    server: "203.0.113.7"
    port: 9531
    uuid: 11111111-2222-3333-4444-555555555555
    network: xhttp
    tls: true
    udp: true
    alpn:
      - h2
    servername: "www.apple.com"
    client-fingerprint: chrome
    encryption: "mlkem768x25519plus.native.0rtt.abc"
    reality-opts:
      public-key: PBK
      short-id: "0011"
    xhttp-opts:
      path: "/abc"
      mode: stream-one
"""
        proxies, _ = importers.parse_proxy_yaml(content)
        self.assertEqual(1, len(proxies))
        node = proxies[0]
        self.assertEqual("xhttp", node["network"])
        self.assertEqual("mlkem768x25519plus.native.0rtt.abc", node["encryption"])
        self.assertEqual({"path": "/abc", "mode": "stream-one"}, node["xhttp-opts"])
        self.assertEqual("0011", node["reality-opts"]["short-id"])

    def test_ruleset_alias_rejects_traversal(self):
        for value in ("..", "../secret", r"..\\secret"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    importers.validate_ruleset_alias(value)


if __name__ == "__main__":
    unittest.main()
