import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import api
import security
import storage


class EmptyConfigRegistrationTest(unittest.TestCase):
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

    def test_success_creates_unconfigured_subscription_and_session(self):
        response = self._register()

        self.assertEqual(303, response.status_code)
        self.assertIn(api.AUTH_COOKIE_NAME, response.cookies)
        user = storage.get_user_by_username("new-user")
        self.assertIsNotNone(user)
        config = storage.get_user_config(int(user["id"]))
        self.assertEqual([], config["proxies"])
        self.assertEqual("", config["final_yaml"])
        self.assertEqual("unknown", config["validation_status"])
        self.assertEqual("", config["published_at"])
        with storage._connect() as conn:
            self.assertEqual(
                1,
                conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0],
            )

        subscription = self.client.get(f"/sub/{config['token']}/config.yaml")
        self.assertEqual(409, subscription.status_code)
        self.assertEqual(
            "该用户尚未保存可用配置",
            subscription.json()["detail"],
        )

    @patch.object(api, "create_auth_session", side_effect=RuntimeError("session failed"))
    def test_session_failure_removes_partial_user_and_config(self, _create_session):
        response = self._register("session-failed")

        self.assertEqual(303, response.status_code)
        self.assertNotIn(api.AUTH_COOKIE_NAME, response.cookies)
        with storage._connect() as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
            self.assertEqual(
                0,
                conn.execute("SELECT COUNT(*) FROM subscription_configs").fetchone()[0],
            )
            self.assertEqual(
                0,
                conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0],
            )

    def test_duplicate_username_is_rejected_without_creating_more_rows(self):
        storage.create_user("duplicate-user", "password123")

        response = self._register("duplicate-user")

        self.assertEqual(303, response.status_code)
        self.assertNotIn(api.AUTH_COOKIE_NAME, response.cookies)
        with storage._connect() as conn:
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
            self.assertEqual(
                1,
                conn.execute("SELECT COUNT(*) FROM subscription_configs").fetchone()[0],
            )
            self.assertEqual(
                0,
                conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0],
            )


if __name__ == "__main__":
    unittest.main()
