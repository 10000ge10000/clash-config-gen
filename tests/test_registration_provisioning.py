import os
import tempfile
import unittest
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient

import api
import security
import storage
from mihomo_validator import ValidationResult
from warp_provisioner import WarpProvisionError


MASQUE_NODE = {
    "name": "预制masque",
    "type": "masque",
    "server": "saas.sin.fan",
    "port": 443,
    "private-key": "private-key-must-not-appear-in-errors",
    "public-key": "public-key",
    "udp": False,
    "network": "h3-l4proxy",
    "sni": "consumer-masque-proxy.cloudflareclient.com",
}


class RegistrationProvisioningTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "APP_DB_PATH": os.path.join(self.tmpdir.name, "app.db"),
                "PUBLIC_BASE_URL": "https://test.local",
                "CSRF_SECRET": "test-secret-that-is-longer-than-thirty-two-characters",
                "ALLOW_REGISTRATION": "true",
                "RULESET_CACHE_ENABLED": "false",
            },
        )
        self.env.start()
        storage.init_db()
        self.client = TestClient(api.app)

    def tearDown(self):
        self.client.close()
        self.env.stop()
        self.tmpdir.cleanup()

    def _register(self, username="new-user"):
        return self.client.post(
            "/sub/auth/register",
            data={
                "username": username,
                "password": "password123",
                "password_confirm": "password123",
                "csrf_token": security.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )

    @patch.object(
        api,
        "validate_with_mihomo",
        return_value=ValidationResult(True, True, "passed", "ok"),
    )
    @patch.object(api, "provision_warp_masque", return_value=MASQUE_NODE)
    def test_success_creates_published_subscription_and_session(self, _provision, _validate):
        response = self._register()

        self.assertEqual(303, response.status_code)
        self.assertIn(api.AUTH_COOKIE_NAME, response.cookies)
        user = storage.get_user_by_username("new-user")
        self.assertIsNotNone(user)
        config = storage.get_user_config(int(user["id"]))
        self.assertEqual("passed", config["validation_status"])
        self.assertTrue(config["published_at"])
        loaded = yaml.safe_load(config["final_yaml"])
        self.assertEqual("预制masque", loaded["proxies"][0]["name"])
        self.assertEqual("h3-l4proxy", loaded["proxies"][0]["network"])
        with storage._connect() as conn:
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0])

    @patch.object(api, "provision_warp_masque", side_effect=WarpProvisionError("WARP 暂不可用"))
    def test_warp_failure_leaves_no_user_config_or_session(self, _provision):
        response = self._register("warp-failed")

        self.assertEqual(303, response.status_code)
        self.assertNotIn(api.AUTH_COOKIE_NAME, response.cookies)
        with storage._connect() as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM subscription_configs").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0])

    @patch.object(
        api,
        "validate_with_mihomo",
        return_value=ValidationResult(True, False, "failed", "private-key-must-not-appear"),
    )
    @patch.object(api, "provision_warp_masque", return_value=MASQUE_NODE)
    def test_mihomo_failure_leaves_no_rows_and_does_not_expose_private_key(
        self, _provision, _validate
    ):
        response = self._register("mihomo-failed")

        self.assertNotIn("private-key", response.headers["location"])
        with storage._connect() as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM subscription_configs").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0])

    @patch.object(api, "provision_warp_masque", return_value=MASQUE_NODE)
    def test_duplicate_username_is_rejected_before_warp_request(self, provision):
        storage.create_user("duplicate-user", "password123")

        response = self._register("duplicate-user")

        self.assertEqual(303, response.status_code)
        provision.assert_not_called()


if __name__ == "__main__":
    unittest.main()
