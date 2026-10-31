import os
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import auth
import importers
import ruleset_updater
import security
import storage
from mihomo_validator import validate_with_mihomo


class ClientIpTests(unittest.TestCase):
    def test_default_trusts_only_loopback(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TRUSTED_PROXY_CIDRS", None)
            self.assertEqual("1.2.3.4", security.request_client_ip("127.0.0.1", "9.9.9.9, 1.2.3.4"))
            self.assertEqual("172.24.0.1", security.request_client_ip("172.24.0.1", "1.2.3.4"))

    def test_docker_gateway_cidr_trusted(self):
        with mock.patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": "127.0.0.1/32, 172.24.0.0/16"}):
            self.assertEqual("1.2.3.4", security.request_client_ip("172.24.0.1", "8.8.8.8, 1.2.3.4"))
            self.assertEqual("203.0.113.9", security.request_client_ip("203.0.113.9", "1.2.3.4"))

    def test_cloudflare_chain_skips_trusted_hops_from_right(self):
        cidrs = "127.0.0.1/32, 172.16.0.0/12, 104.16.0.0/13"
        with mock.patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": cidrs}):
            # Cloudflare 追加真实客户端，OpenResty 再追加 Cloudflare 边缘地址
            self.assertEqual("198.51.100.7", security.request_client_ip("172.24.0.1", "198.51.100.7, 104.16.1.2"))
            # 客户端伪造的左侧条目被忽略
            self.assertEqual(
                "198.51.100.7",
                security.request_client_ip("172.24.0.1", "1.1.1.1, 198.51.100.7, 104.16.1.2"),
            )
            # 绕过 Cloudflare 直连源站时，OpenResty 追加的是攻击者自身地址
            self.assertEqual("203.0.113.5", security.request_client_ip("172.24.0.1", "104.16.9.9, 203.0.113.5"))
            # 非法条目视为边界，取其右侧最近的地址
            self.assertEqual("104.16.1.2", security.request_client_ip("172.24.0.1", "bogus, 104.16.1.2"))

    def test_invalid_cidr_ignored_with_warning(self):
        with mock.patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": "not-a-cidr,172.24.0.0/16"}):
            with self.assertLogs("security", level="WARNING"):
                self.assertEqual("1.2.3.4", security.request_client_ip("172.24.0.1", "1.2.3.4"))

    def test_ipv6_peer_does_not_match_ipv4_network(self):
        with mock.patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": "127.0.0.1/32"}):
            self.assertEqual("::1", security.request_client_ip("::1", "1.2.3.4"))


class CsrfSecretTests(unittest.TestCase):
    def test_placeholders_rejected(self):
        for value in (
            "replace-with-at-least-32-random-characters",
            "replace-with-output-of-openssl-rand-hex-32",
            "please-change-me-please-change-me-0123456789",
            "xxxxxxxx-change-this-xxxxxxxxxxxxxxxxxxxxxxxx",
        ):
            with mock.patch.dict(os.environ, {"CSRF_SECRET": value}):
                with self.assertRaises(RuntimeError):
                    security.create_csrf_token("x")

    def test_known_good_values_accepted(self):
        for value in (
            "ci-only-secret-that-is-longer-than-thirty-two-characters",
            "test-secret-that-is-longer-than-thirty-two-characters",
        ):
            with mock.patch.dict(os.environ, {"CSRF_SECRET": value}):
                self.assertTrue(security.validate_csrf_token(security.create_csrf_token("x"), "x"))


class PublicBaseUrlTests(unittest.TestCase):
    def test_empty_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PUBLIC_BASE_URL", None)
            self.assertEqual("", storage.get_public_base_url())
            import config_builder
            url = config_builder.get_dustinwin_provider_url("x.mrs", "https://up.example/x.mrs")
            self.assertEqual("https://up.example/x.mrs", url)

    def test_strips_trailing_slash(self):
        with mock.patch.dict(os.environ, {"PUBLIC_BASE_URL": "https://a.example/"}):
            self.assertEqual("https://a.example", storage.get_public_base_url())


class StorageHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"APP_DB_PATH": os.path.join(self.tmp.name, "app.db")})
        self.env.start()
        storage.init_db()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_wal_enabled(self):
        with storage._db() as conn:
            self.assertEqual("wal", conn.execute("PRAGMA journal_mode").fetchone()[0])

    def test_unparsable_proxies_json_preserved(self):
        user = storage.create_user("alice", "password-123")
        with storage._db() as conn:
            conn.execute("UPDATE subscription_configs SET proxies_json = ? WHERE user_id = ?", ("{broken", user["id"]))
        with self.assertLogs("storage", level="WARNING"):
            with storage._db() as conn:
                storage._migrate_mihomo_proxy_fields(conn)
        with storage._db() as conn:
            value = conn.execute("SELECT proxies_json FROM subscription_configs").fetchone()[0]
        self.assertEqual("{broken", value)

    def test_unknown_user_runs_dummy_hash(self):
        with mock.patch.object(storage, "verify_dummy_password") as dummy:
            self.assertIsNone(storage.authenticate_user("ghost", "whatever"))
            dummy.assert_called_once()
        user = storage.create_user("bob", "password-123")
        storage.set_user_enabled(int(user["id"]), False)
        with mock.patch.object(storage, "verify_dummy_password") as dummy:
            self.assertIsNone(storage.authenticate_user("bob", "password-123"))
            dummy.assert_called_once()

    def test_last_used_throttled(self):
        user = storage.create_user("carol", "password-123")
        token = storage.create_auth_session(int(user["id"]))

        def last_used():
            with storage._db() as conn:
                return conn.execute("SELECT last_used_at FROM auth_sessions").fetchone()[0]

        first = last_used()
        self.assertIsNotNone(storage.get_user_by_auth_session(token))
        self.assertEqual(first, last_used())
        old = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec="seconds")
        with storage._db() as conn:
            conn.execute("UPDATE auth_sessions SET last_used_at = ?", (old,))
        self.assertIsNotNone(storage.get_user_by_auth_session(token))
        self.assertNotEqual(old, last_used())

    def test_expired_cleanup_throttled(self):
        user = storage.create_user("dave", "password-123")
        token = storage.create_auth_session(int(user["id"]))
        storage.get_user_by_auth_session(token)  # 记录一次清理时间
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
        with storage._db() as conn:
            conn.execute(
                "INSERT INTO auth_sessions (user_id, token_hash, expires_at, created_at, last_used_at)"
                " VALUES (?, 'stale', ?, ?, ?)",
                (user["id"], past, past, past),
            )
        storage.get_user_by_auth_session(token)
        with storage._db() as conn:
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM auth_sessions WHERE token_hash='stale'").fetchone()[0])
        storage._session_cleanup_last_run.clear()
        storage.get_user_by_auth_session(token)
        with storage._db() as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM auth_sessions WHERE token_hash='stale'").fetchone()[0])

    def test_admin_env_does_not_promote_normal_user(self):
        storage.create_user("erin", "password-123")
        with mock.patch.dict(os.environ, {"ADMIN_USERNAME": "erin", "ADMIN_PASSWORD": "another-pass-1"}):
            with self.assertLogs("storage", level="ERROR"):
                storage.ensure_admin_from_env()
        self.assertEqual(0, int(storage.get_user_by_username("erin")["is_admin"]))

    def test_existing_admin_password_not_overwritten(self):
        storage.create_user("root1", "first-password", is_admin=True)
        with mock.patch.dict(os.environ, {"ADMIN_USERNAME": "root1", "ADMIN_PASSWORD": "second-password"}):
            with self.assertLogs("storage", level="INFO") as logs:
                storage.ensure_admin_from_env()
        self.assertTrue(any("忽略 ADMIN_PASSWORD" in line for line in logs.output))
        self.assertIsNotNone(storage.authenticate_user("root1", "first-password"))
        self.assertIsNone(storage.authenticate_user("root1", "second-password"))

    def test_empty_admin_password_creates_nothing(self):
        with mock.patch.dict(os.environ, {"ADMIN_USERNAME": "adminx", "ADMIN_PASSWORD": ""}):
            storage.ensure_admin_from_env()
        self.assertIsNone(storage.get_user_by_username("adminx"))


class _SlowResponse:
    status_code = 200
    headers = {"content-type": "text/plain"}
    encoding = "utf-8"

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=0):
        while True:
            time.sleep(0.05)
            yield b"x"

    def close(self):
        pass


class FetchDeadlineTests(unittest.TestCase):
    def test_slow_drip_hits_deadline(self):
        with mock.patch.dict(os.environ, {"EXTERNAL_FETCH_DEADLINE_SECONDS": "0.3"}), \
                mock.patch.object(importers, "_resolve_public_external_url", return_value=("http://example.com/", ["93.184.216.34"])), \
                mock.patch("requests.Session.get", return_value=_SlowResponse()):
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, "超时"):
                importers.fetch_text_from_external_url("http://example.com/")
            self.assertLess(time.monotonic() - started, 3)

    def test_invalid_deadline_env_falls_back(self):
        with mock.patch.dict(os.environ, {"EXTERNAL_FETCH_DEADLINE_SECONDS": "abc"}):
            self.assertEqual(30.0, importers._external_fetch_deadline_seconds())


class RulesetUpdaterTests(unittest.TestCase):
    def test_unique_temp_and_loop_survives_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path
            response = mock.Mock(content=b"payload")
            response.raise_for_status = lambda: None
            with mock.patch.object(ruleset_updater, "RULESET_CACHE_DIR", Path(tmp)), \
                    mock.patch.object(ruleset_updater.requests, "get", return_value=response):
                stats = ruleset_updater.update_dustinwin_rulesets()
            self.assertEqual(0, stats["failed"])
            self.assertEqual([], [p for p in os.listdir(tmp) if p.endswith(".tmp")])

        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("boom")
            return {"updated": 0, "failed": 0}

        def stop_after_two(_seconds):
            if calls["n"] >= 2:
                raise KeyboardInterrupt

        with mock.patch.object(ruleset_updater, "update_dustinwin_rulesets", side_effect=flaky), \
                mock.patch.object(ruleset_updater.time, "sleep", side_effect=stop_after_two):
            with self.assertLogs("ruleset_updater", level="ERROR"):
                with self.assertRaises(KeyboardInterrupt):
                    ruleset_updater._background_loop()
        self.assertEqual(2, calls["n"])


class MihomoHomeTests(unittest.TestCase):
    def test_passes_home_dir_and_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            captured = {}

            def fake_run(cmd, **kwargs):
                captured["cmd"] = cmd
                return mock.Mock(returncode=0, stdout="ok", stderr="")

            with mock.patch.dict(os.environ, {"MIHOMO_HOME": home, "MIHOMO_VALIDATE_ENABLED": "true"}), \
                    mock.patch("mihomo_validator.shutil.which", return_value="/bin/mihomo"), \
                    mock.patch("mihomo_validator.subprocess.run", side_effect=fake_run):
                self.assertTrue(validate_with_mihomo("a: 1").ok)
            self.assertIn("-d", captured["cmd"])
            self.assertEqual(home, captured["cmd"][captured["cmd"].index("-d") + 1])
            self.assertTrue(os.path.isdir(home))

            # 不可创建时回退临时目录
            with mock.patch.dict(os.environ, {"MIHOMO_HOME": "/proc/nope/x", "MIHOMO_VALIDATE_ENABLED": "true"}), \
                    mock.patch("mihomo_validator.shutil.which", return_value="/bin/mihomo"), \
                    mock.patch("mihomo_validator.subprocess.run", side_effect=fake_run):
                self.assertTrue(validate_with_mihomo("a: 1").ok)
            self.assertIn("mihomo-home-", captured["cmd"][captured["cmd"].index("-d") + 1])


if __name__ == "__main__":
    unittest.main()
