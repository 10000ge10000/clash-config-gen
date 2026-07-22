import os
import tempfile
import unittest

from fastapi.testclient import TestClient

import api
import security
import storage


class AuthSecurityTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.previous_env = {
            name: os.environ.get(name)
            for name in (
                "APP_DB_PATH",
                "PUBLIC_BASE_URL",
                "CSRF_SECRET",
                "ALLOW_REGISTRATION",
                "RULESET_CACHE_ENABLED",
                "AUTH_RATE_LIMIT_ACCOUNT_FAILURES",
                "AUTH_RATE_LIMIT_IP_FAILURES",
                "AUTH_RATE_LIMIT_WINDOW_SECONDS",
            )
        }
        os.environ.update(
            {
                "APP_DB_PATH": os.path.join(self.tmpdir.name, "app.db"),
                "PUBLIC_BASE_URL": "https://test.local",
                "CSRF_SECRET": "test-secret-that-is-longer-than-thirty-two-characters",
                "ALLOW_REGISTRATION": "false",
                "RULESET_CACHE_ENABLED": "false",
                "AUTH_RATE_LIMIT_ACCOUNT_FAILURES": "2",
                "AUTH_RATE_LIMIT_IP_FAILURES": "10",
                "AUTH_RATE_LIMIT_WINDOW_SECONDS": "900",
            }
        )
        storage.init_db()
        storage.create_user("secure-user", "password123")
        self.client = TestClient(api.app)

    def tearDown(self):
        self.client.close()
        for name, value in self.previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self.tmpdir.cleanup()

    def _login(self, password: str, token: str | None = None, origin: str = "https://test.local"):
        return self.client.post(
            "/sub/auth/login",
            data={
                "username": "secure-user",
                "password": password,
                "csrf_token": token or security.create_csrf_token("auth"),
            },
            headers={"Origin": origin},
            follow_redirects=False,
        )

    def test_csrf_token_is_scoped_and_expires(self):
        token = security.create_csrf_token("auth", now=1_000)
        self.assertTrue(security.validate_csrf_token(token, "auth", now=1_300))
        self.assertFalse(security.validate_csrf_token(token, "logout", now=1_300))
        self.assertFalse(security.validate_csrf_token(token, "auth", now=5_000))

    def test_login_rejects_untrusted_origin(self):
        response = self._login("password123", origin="https://evil.example")

        self.assertEqual(303, response.status_code)
        self.assertIn("auth_error", response.headers["location"])
        with storage._connect() as conn:
            event = conn.execute(
                "SELECT event_type, detail FROM auth_audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual("login_rejected", event["event_type"])
        self.assertEqual("csrf_or_origin", event["detail"])

    def test_login_rate_limit_blocks_after_failed_attempts(self):
        self.assertEqual(303, self._login("wrong-password").status_code)
        self.assertEqual(303, self._login("wrong-password").status_code)

        blocked = self._login("password123")

        self.assertEqual(303, blocked.status_code)
        self.assertEqual("900", blocked.headers["retry-after"])
        self.assertNotIn(api.AUTH_COOKIE_NAME, blocked.cookies)

    def test_successful_login_is_audited_without_secrets(self):
        response = self._login("password123")

        self.assertEqual(303, response.status_code)
        self.assertIn(api.AUTH_COOKIE_NAME, response.cookies)
        with storage._connect() as conn:
            event = conn.execute(
                "SELECT * FROM auth_audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual("login", event["event_type"])
        self.assertEqual(1, event["success"])
        self.assertNotIn("password123", event["detail"])


if __name__ == "__main__":
    unittest.main()
