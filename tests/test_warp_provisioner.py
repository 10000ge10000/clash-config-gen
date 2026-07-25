import base64
import os
import unittest
from unittest.mock import patch

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from warp_provisioner import WarpProvisionError, provision_warp_masque


def server_public_pem() -> str:
    return (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


class FakeResponse:
    def __init__(self, status_code=200, payload=None, invalid_json=False):
        self.status_code = status_code
        self.payload = payload
        self.invalid_json = invalid_json

    def json(self):
        if self.invalid_json:
            raise ValueError("invalid")
        return self.payload


class FakeSession:
    def __init__(self, post_result, patch_result=None):
        self.post_result = post_result
        self.patch_result = patch_result
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        if isinstance(self.post_result, Exception):
            raise self.post_result
        return self.post_result

    def patch(self, url, **kwargs):
        self.calls.append(("patch", url, kwargs))
        if isinstance(self.patch_result, Exception):
            raise self.patch_result
        return self.patch_result


def successful_session():
    return FakeSession(
        FakeResponse(payload={"id": "registration-id", "token": "access-token"}),
        FakeResponse(payload={"config": {"peers": [{"public_key": server_public_pem()}]}}),
    )


class WarpProvisionerTest(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {
                "WARP_PROVISION_ENABLED": "true",
                "WARP_API_BASE_URL": "https://warp.test",
                "WARP_PRESET_NAME": "预制masque",
                "WARP_PRESET_SERVER": "saas.sin.fan",
            },
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_success_returns_h3_l4proxy_node_without_registration_credentials(self):
        session = successful_session()

        proxy = provision_warp_masque(session)

        self.assertEqual("预制masque", proxy["name"])
        self.assertEqual("masque", proxy["type"])
        self.assertEqual("saas.sin.fan", proxy["server"])
        self.assertEqual("h3-l4proxy", proxy["network"])
        self.assertIs(False, proxy["udp"])
        self.assertNotIn("ip", proxy)
        self.assertNotIn("ipv6", proxy)
        self.assertNotIn("mtu", proxy)
        self.assertNotIn("token", proxy)
        self.assertNotIn("registration-id", str(proxy))
        patch_call = session.calls[1][2]
        self.assertEqual("secp256r1", patch_call["json"]["key_type"])
        self.assertTrue(patch_call["json"]["name"].startswith("ccg-"))
        self.assertNotIn("username", patch_call["json"]["name"])

    def test_two_provisions_have_independent_private_keys_and_nodes(self):
        first = provision_warp_masque(successful_session())
        second = provision_warp_masque(successful_session())

        self.assertNotEqual(first["private-key"], second["private-key"])
        self.assertNotEqual(first, second)

    def test_timeout_is_sanitized(self):
        with self.assertRaisesRegex(WarpProvisionError, "失败或超时") as caught:
            provision_warp_masque(FakeSession(requests.Timeout("private-token")))
        self.assertNotIn("private-token", str(caught.exception))

    def test_429_is_reported_without_response_body(self):
        with self.assertRaisesRegex(WarpProvisionError, "请求过于频繁"):
            provision_warp_masque(
                FakeSession(FakeResponse(status_code=429, payload={"secret": "do-not-log"}))
            )

    def test_invalid_json_is_rejected(self):
        with self.assertRaisesRegex(WarpProvisionError, "无效 JSON"):
            provision_warp_masque(FakeSession(FakeResponse(invalid_json=True)))

    def test_missing_peer_is_rejected(self):
        with self.assertRaisesRegex(WarpProvisionError, "缺少 peer"):
            provision_warp_masque(
                FakeSession(
                    FakeResponse(payload={"id": "id", "token": "token"}),
                    FakeResponse(payload={"config": {"peers": []}}),
                )
            )

    def test_invalid_public_key_is_rejected(self):
        invalid_pem = base64.b64encode(b"not-a-public-key").decode("ascii")
        with self.assertRaisesRegex(WarpProvisionError, "公钥格式错误"):
            provision_warp_masque(
                FakeSession(
                    FakeResponse(payload={"id": "id", "token": "token"}),
                    FakeResponse(
                        payload={"config": {"peers": [{"public_key": invalid_pem}]}}
                    ),
                )
            )


if __name__ == "__main__":
    unittest.main()
