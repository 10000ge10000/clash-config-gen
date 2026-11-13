"""api.py 加固项回归测试：事件循环阻塞、访问日志脱敏、登录并发、启动清理、
/health 字段、请求体与注册限流、安全响应头、订阅缓存。"""

import asyncio
import logging
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import api
import auth_service
import draft_service
import security
import storage


VALID_SUBSCRIPTION_YAML = """\
proxies:
- name: node-1
  type: ss
  server: example.com
  port: 8388
  cipher: aes-128-gcm
  password: secret
proxy-groups:
- name: Proxy
  type: select
  proxies:
  - node-1
rules:
- MATCH,Proxy
"""


def _assert_not_in_event_loop():
    """阻塞函数必须运行在线程池里：线程池线程没有正在运行的事件循环。"""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise AssertionError("阻塞调用运行在事件循环线程中")


class HardeningTestBase(unittest.TestCase):
    ENV_NAMES = (
        "APP_DB_PATH",
        "PUBLIC_BASE_URL",
        "CSRF_SECRET",
        "ALLOW_REGISTRATION",
        "AUTH_COOKIE_SECURE",
        "RULESET_CACHE_ENABLED",
        "AUTH_RATE_LIMIT_ACCOUNT_FAILURES",
        "AUTH_RATE_LIMIT_IP_FAILURES",
        "AUTH_RATE_LIMIT_WINDOW_SECONDS",
        "MIHOMO_VALIDATE_ENABLED",
        "RULESET_DIR",
        "REGISTER_RATE_LIMIT_PER_WINDOW",
        "REGISTER_RATE_LIMIT_WINDOW_SECONDS",
        "ADMIN_USERNAME",
        "ADMIN_PASSWORD",
    )

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.previous_env = {name: os.environ.get(name) for name in self.ENV_NAMES}
        for name in ("ADMIN_USERNAME", "ADMIN_PASSWORD", "REGISTER_RATE_LIMIT_PER_WINDOW"):
            os.environ.pop(name, None)
        os.environ.update(
            {
                "APP_DB_PATH": os.path.join(self.tmpdir.name, "app.db"),
                "PUBLIC_BASE_URL": "https://test.local",
                "CSRF_SECRET": "test-secret-that-is-longer-than-thirty-two-characters",
                "ALLOW_REGISTRATION": "false",
                "AUTH_COOKIE_SECURE": "false",
                "RULESET_CACHE_ENABLED": "false",
                "AUTH_RATE_LIMIT_ACCOUNT_FAILURES": "2",
                "AUTH_RATE_LIMIT_IP_FAILURES": "100",
                "AUTH_RATE_LIMIT_WINDOW_SECONDS": "900",
                "MIHOMO_VALIDATE_ENABLED": "false",
                "RULESET_DIR": os.path.join(self.tmpdir.name, "ruleset"),
            }
        )
        with auth_service._REGISTER_ATTEMPTS_GUARD:
            auth_service._REGISTER_ATTEMPTS.clear()
        storage.init_db()
        self.client = TestClient(api.app)

    def tearDown(self):
        self.client.close()
        with auth_service._REGISTER_ATTEMPTS_GUARD:
            auth_service._REGISTER_ATTEMPTS.clear()
        for name, value in self.previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self.tmpdir.cleanup()

    def _headers(self):
        # api 用途 token 绑定当前客户端 Cookie 中的会话。
        binding = security.csrf_session_binding(self.client.cookies.get(api.AUTH_COOKIE_NAME, ""))
        return {"Origin": "https://test.local", "X-CSRF-Token": security.create_csrf_token("api", binding=binding)}

    def _login(self, username, password="password123"):
        response = self.client.post(
            "/sub/auth/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": security.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        self.assertEqual(303, response.status_code)
        self.assertIn(api.AUTH_COOKIE_NAME, response.cookies)
        return response


class EventLoopOffloadTest(HardeningTestBase):
    """问题 1：async 路由里的阻塞工作必须在线程池执行。"""

    def test_builtin_ruleset_route_serves_cached_files(self):
        """走真实 HTTP 路由下载内置规则集：DustinWin 与 MetaCubeX 的文件都能取到，来源头正确。"""
        import ruleset_updater

        previous_cache_dir = ruleset_updater.RULESET_CACHE_DIR
        ruleset_updater.RULESET_CACHE_DIR = Path(self.tmpdir.name)
        try:
            Path(self.tmpdir.name, "ai.mrs").write_bytes(b"ai-data")
            Path(self.tmpdir.name, "scholar.mrs").write_bytes(b"scholar-data")
            ai = self.client.get("/ruleset/dustinwin/ai.mrs")
            scholar = self.client.get("/ruleset/dustinwin/scholar.mrs")
            missing = self.client.get("/ruleset/dustinwin/not-a-ruleset.mrs")
        finally:
            ruleset_updater.RULESET_CACHE_DIR = previous_cache_dir

        self.assertEqual(200, ai.status_code)
        self.assertEqual(b"ai-data", ai.content)
        self.assertEqual("DustinWin/ruleset_geodata", ai.headers["x-clash-ruleset-source"])
        self.assertEqual(200, scholar.status_code)
        self.assertEqual("MetaCubeX/meta-rules-dat", scholar.headers["x-clash-ruleset-source"])
        self.assertEqual(404, missing.status_code)

    def test_api_login_runs_password_check_in_threadpool(self):
        storage.create_user("loop-user", "password123")
        original = auth_service.authenticate_user

        def checked(*args, **kwargs):
            _assert_not_in_event_loop()
            return original(*args, **kwargs)

        with patch.object(auth_service, "authenticate_user", side_effect=checked) as mocked:
            response = self.client.post(
                "/api/auth/login",
                json={
                    "username": "loop-user",
                    "password": "password123",
                    "csrf_token": security.create_csrf_token("auth"),
                },
                headers={"Origin": "https://test.local"},
            )
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual(1, mocked.call_count)

    def test_import_and_ruleset_test_url_fetch_in_threadpool(self):
        storage.create_user("fetch-user", "password123")
        self._login("fetch-user")

        def fake_fetch(url, timeout=15):
            _assert_not_in_event_loop()
            return "payload:\n- DOMAIN,example.com\n", "text/plain"

        with patch.object(api, "fetch_text_from_external_url", side_effect=fake_fetch) as mocked:
            tested = self.client.post(
                "/api/ruleset/test-url",
                json={"url": "https://rules.example.com/a.yaml"},
                headers=self._headers(),
            )
            imported = self.client.post(
                "/api/import",
                json={"mode": "url", "url": "https://sub.example.com/x", "existing_proxies": []},
                headers=self._headers(),
            )
        self.assertEqual(200, tested.status_code, tested.text)
        # 导入内容不是节点 YAML，这里只关心抓取发生在线程池里。
        self.assertIn(imported.status_code, {200, 400}, imported.text)
        self.assertEqual(2, mocked.call_count)

    def test_validate_runs_mihomo_and_lock_in_threadpool(self):
        storage.create_user("validate-user", "password123")
        self._login("validate-user")
        original_lock = api._ruleset_user_lock

        def checked_lock(user_id):
            _assert_not_in_event_loop()
            return original_lock(user_id)

        def fake_mihomo(_yaml_text):
            _assert_not_in_event_loop()
            return type("Result", (), {"status": "passed", "ok": True, "message": "ok"})()

        body = {
            "proxies": [
                {
                    "name": "node-1",
                    "type": "ss",
                    "server": "example.com",
                    "port": 8388,
                    "cipher": "aes-128-gcm",
                    "password": "secret",
                }
            ],
            "custom_rules": [],
            "custom_rule_providers": {},
        }
        with patch.object(api, "_ruleset_user_lock", side_effect=checked_lock) as lock_mock, patch.object(
            draft_service, "validate_with_mihomo", side_effect=fake_mihomo
        ) as mihomo_mock:
            response = self.client.post("/api/validate", json=body, headers=self._headers())
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual(1, lock_mock.call_count)
        self.assertEqual(1, mihomo_mock.call_count)


class AccessLogRedactionTest(unittest.TestCase):
    """问题 2：uvicorn 访问日志不得包含订阅 token。"""

    def _format(self, path):
        record = logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            1,
            '%s - "%s %s HTTP/%s" %d',
            ("203.0.113.9:5000", "GET", path, "1.1", 200),
            None,
        )
        logger = logging.getLogger("uvicorn.access")
        self.assertTrue(logger.filter(record))
        return record.getMessage()

    def test_filter_is_installed_on_uvicorn_access_logger(self):
        filters = logging.getLogger("uvicorn.access").filters
        self.assertTrue(any(isinstance(item, api._AccessLogTokenFilter) for item in filters))

    def test_subscription_and_ruleset_tokens_are_redacted(self):
        token = "Zx9-SecretToken_abc"
        cases = {
            f"/sub/{token}": "/sub/<redacted>",
            f"/sub/{token}/config.yaml?flag=1": "/sub/<redacted>/config.yaml?flag=1",
            f"/sub/{token}/diagnostics": "/sub/<redacted>/diagnostics",
            f"/ruleset/user/{token}/7/a--{'0' * 64}.yaml": f"/ruleset/user/<redacted>/7/a--{'0' * 64}.yaml",
        }
        for raw, expected in cases.items():
            message = self._format(raw)
            self.assertNotIn(token, message)
            self.assertIn(expected, message)
            self.assertIn("203.0.113.9:5000", message)

    def test_fixed_routes_are_kept(self):
        for path in ("/sub/auth/login", "/sub/assets/auth-future-city.png", "/api/config", "/health"):
            self.assertIn(path, self._format(path))

    def test_records_are_never_dropped(self):
        record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, "plain message", None, None)
        self.assertTrue(api._AccessLogTokenFilter().filter(record))
        self.assertEqual("plain message", record.getMessage())


class LifespanTest(HardeningTestBase):
    """问题 3 / 5：启动配置检查与空用户表保护。"""

    def test_missing_public_base_url_fails_startup(self):
        os.environ.pop("PUBLIC_BASE_URL", None)
        with patch.object(api, "start_ruleset_update_worker") as worker:
            with self.assertRaises(RuntimeError) as ctx:
                with TestClient(api.app):
                    pass
        self.assertIn("PUBLIC_BASE_URL", str(ctx.exception))
        worker.assert_not_called()

    def test_empty_user_table_skips_startup_cleanup_even_with_env_admin(self):
        os.environ["ADMIN_USERNAME"] = "env-admin"
        os.environ["ADMIN_PASSWORD"] = "password123"
        with patch.object(api, "start_ruleset_update_worker"), patch.object(
            api, "_retry_ruleset_tombstones"
        ) as retry:
            with TestClient(api.app):
                pass
        retry.assert_not_called()
        self.assertIsNotNone(storage.get_user_by_username("env-admin"))

    def test_existing_users_run_startup_cleanup(self):
        storage.create_user("existing-user", "password123")
        with patch.object(api, "start_ruleset_update_worker"), patch.object(
            api, "_retry_ruleset_tombstones", return_value=[]
        ) as retry:
            with TestClient(api.app):
                pass
        retry.assert_called_once_with()

    def test_retry_with_empty_user_table_keeps_orphans_and_tombstones(self):
        ruleset_dir = Path(os.environ["RULESET_DIR"])
        orphan = ruleset_dir / "users" / "42"
        orphan.mkdir(parents=True)
        (orphan / "kept.yaml").write_bytes(b"kept")
        tombstone = ruleset_dir / ".trash" / ("43-" + "d" * 32)
        tombstone.mkdir(parents=True)
        (tombstone / "kept.yaml").write_bytes(b"kept")

        self.assertEqual([], api._retry_ruleset_tombstones())
        self.assertTrue((orphan / "kept.yaml").is_file())
        self.assertTrue((tombstone / "kept.yaml").is_file())

        # 有用户之后：首次先认领规则集目录（写实例标记）并跳过孤儿清理，tombstone 照常处理；
        # 下一次起恢复正常的孤儿回收。
        storage.create_user("someone", "password123")
        self.assertEqual([], api._retry_ruleset_tombstones())
        self.assertTrue((orphan / "kept.yaml").is_file())
        self.assertFalse(tombstone.exists())
        self.assertTrue((ruleset_dir / ".db-instance-id").is_file())
        self.assertEqual([], api._retry_ruleset_tombstones())
        self.assertFalse(orphan.exists())


class LoginConcurrencyTest(HardeningTestBase):
    """问题 4：并发错误密码不能绕过账号失败阈值。"""

    def test_concurrent_failures_cannot_exceed_account_limit(self):
        storage.create_user("race-user", "password123")
        original = auth_service.authenticate_user

        def slow_authenticate(*args, **kwargs):
            # 拉宽“检查阈值”与“记录失败”之间的窗口。
            time.sleep(0.05)
            return original(*args, **kwargs)

        results = []
        start = threading.Barrier(8)

        def attempt():
            start.wait()
            results.append(auth_service._try_login("Race-User ", "wrong-password", False, "198.51.100.7"))

        with patch.object(auth_service, "authenticate_user", side_effect=slow_authenticate) as mocked:
            threads = [threading.Thread(target=attempt) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)

        self.assertEqual(8, len(results))
        # 阈值为 2：最多只有 2 次真正校验密码，其余全部被限流。
        self.assertEqual(2, mocked.call_count)
        self.assertEqual(6, sum(1 for item in results if item["blocked"]))

    def test_same_username_variants_share_one_lock(self):
        self.assertIs(auth_service._login_lock_for("alice"), auth_service._login_lock_for("alice"))


class HealthTest(HardeningTestBase):
    """问题 6：/health 未认证时不暴露数据库路径与用户规模。"""

    def test_unauthenticated_health_hides_sensitive_fields(self):
        response = self.client.get("/health")
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertEqual("ok", data["status"])
        for key in ("database", "users", "configs"):
            self.assertNotIn(key, data)
        self.assertNotIn(os.environ["APP_DB_PATH"], response.text)
        self.assertTrue(data["database_ok"])

    def test_regular_user_gets_reduced_health(self):
        storage.create_user("plain-user", "password123")
        self._login("plain-user")
        data = self.client.get("/health").json()
        self.assertNotIn("users", data)

    def test_admin_gets_full_snapshot(self):
        storage.create_user("health-admin", "password123", is_admin=True)
        self._login("health-admin")
        data = self.client.get("/health").json()
        self.assertEqual("ok", data["status"])
        self.assertEqual(1, data["users"])
        self.assertIn("database", data)


class BodyLimitAndRegisterRateTest(HardeningTestBase):
    """问题 7：请求体流式限长与注册频率限制。"""

    def test_declared_oversized_body_is_rejected(self):
        response = self.client.post(
            "/api/auth/login",
            content=b"{" + b" " * (api.MAX_DRAFT_BODY_BYTES + 10) + b"}",
            headers={"Origin": "https://test.local", "Content-Type": "application/json"},
        )
        self.assertEqual(413, response.status_code)

    def test_chunked_oversized_body_is_rejected_while_streaming(self):
        chunk = b" " * (256 * 1024)

        def body():
            # 生成器请求体没有 Content-Length，只能靠流式累加判定超限。
            yield b"{"
            for _ in range(64):  # 共 16MB，远超上限
                yield chunk
            yield b"}"

        response = self.client.post(
            "/api/auth/login",
            content=body(),
            headers={"Origin": "https://test.local", "Content-Type": "application/json"},
        )
        self.assertEqual(413, response.status_code)

    def test_small_body_still_parses(self):
        response = self.client.post(
            "/api/auth/login",
            content=b"[]",
            headers={"Origin": "https://test.local", "Content-Type": "application/json"},
        )
        self.assertEqual(400, response.status_code)
        self.assertEqual("JSON 顶层必须是对象", response.json()["error"])

    def _register_json(self, username):
        return self.client.post(
            "/api/auth/register",
            json={
                "username": username,
                "password": "password123",
                "password_confirm": "password123",
                "csrf_token": security.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
        )

    def test_json_registration_is_rate_limited_per_ip(self):
        os.environ["ALLOW_REGISTRATION"] = "true"
        os.environ["REGISTER_RATE_LIMIT_PER_WINDOW"] = "2"
        os.environ["REGISTER_RATE_LIMIT_WINDOW_SECONDS"] = "3600"
        self.assertEqual(200, self._register_json("reg-one").status_code)
        self.assertEqual(200, self._register_json("reg-two").status_code)
        blocked = self._register_json("reg-three")
        self.assertEqual(429, blocked.status_code)
        self.assertEqual("3600", blocked.headers.get("retry-after"))
        self.assertIsNone(storage.get_user_by_username("reg-three"))

    def test_form_registration_shares_rate_limit(self):
        os.environ["ALLOW_REGISTRATION"] = "true"
        os.environ["REGISTER_RATE_LIMIT_PER_WINDOW"] = "1"
        self.assertEqual(200, self._register_json("form-one").status_code)
        response = self.client.post(
            "/sub/auth/register",
            data={
                "username": "form-two",
                "password": "password123",
                "password_confirm": "password123",
                "csrf_token": security.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        self.assertEqual(303, response.status_code)
        self.assertIn("auth_error=", response.headers["location"])
        self.assertIsNotNone(response.headers.get("retry-after"))
        self.assertIsNone(storage.get_user_by_username("form-two"))

    def test_disabled_registration_does_not_consume_quota(self):
        os.environ["REGISTER_RATE_LIMIT_PER_WINDOW"] = "1"
        self.assertEqual(403, self._register_json("closed-one").status_code)
        self.assertEqual(403, self._register_json("closed-two").status_code)
        os.environ["ALLOW_REGISTRATION"] = "true"
        self.assertEqual(200, self._register_json("open-one").status_code)


class SecurityHeadersTest(HardeningTestBase):
    """问题 9：所有响应带安全头；HTML 主页 no-cache；https 才加 HSTS。"""

    EXPECTED = {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "same-origin",
        "content-security-policy": (
            "default-src 'self'; "
            "script-src 'self' https://static.cloudflareinsights.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self' https://cloudflareinsights.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "form-action 'self'"
        ),
    }

    def _assert_security_headers(self, response):
        for name, value in self.EXPECTED.items():
            self.assertEqual(value, response.headers.get(name), name)
        policy = response.headers.get("permissions-policy", "")
        for feature in ("camera=()", "microphone=()", "geolocation=()"):
            self.assertIn(feature, policy)

    def test_html_json_and_error_responses_have_headers(self):
        root = self.client.get("/")
        if root.status_code == 200:
            self.assertEqual("no-cache", root.headers.get("cache-control"))
        self._assert_security_headers(root)
        self._assert_security_headers(self.client.get("/api/session"))
        self._assert_security_headers(self.client.get("/sub/not-a-real-token"))
        self._assert_security_headers(self.client.get("/health"))

    def test_hsts_only_for_https_public_base_url(self):
        self.assertEqual("max-age=31536000", self.client.get("/health").headers.get("strict-transport-security"))
        os.environ["PUBLIC_BASE_URL"] = "http://test.local"
        self.assertIsNone(self.client.get("/health").headers.get("strict-transport-security"))

    def test_subscription_headers_are_not_duplicated(self):
        user = storage.create_user("header-user", "password123")
        token = self._publish_raw_yaml(int(user["id"]), VALID_SUBSCRIPTION_YAML)
        response = self.client.get(f"/sub/{token}")
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual(["nosniff"], response.headers.get_list("x-content-type-options"))

    def _publish_raw_yaml(self, user_id, final_yaml):
        token = storage.get_user_config(user_id)["token"]
        with storage._db() as conn:
            conn.execute(
                "UPDATE subscription_configs SET final_yaml = ? WHERE user_id = ?",
                (final_yaml, user_id),
            )
        return token


class SubscriptionResponseTest(HardeningTestBase):
    """问题 8 / 10：非 /api 错误不回显详情；HEAD 与缓存行为。"""

    def setUp(self):
        super().setUp()
        with api._SUBSCRIPTION_CACHE_GUARD:
            api._SUBSCRIPTION_CACHE.clear()
        self.user = storage.create_user("sub-user", "password123")
        self.user_id = int(self.user["id"])

    def _set_yaml(self, final_yaml):
        with storage._db() as conn:
            conn.execute(
                "UPDATE subscription_configs SET final_yaml = ? WHERE user_id = ?",
                (final_yaml, self.user_id),
            )
        return storage.get_user_config(self.user_id)["token"]

    def test_corrupted_yaml_returns_generic_message(self):
        token = self._set_yaml("proxies: [unclosed\n  - : : 'secret-detail")
        with self.assertLogs(api.LOGGER, level="WARNING") as logs:
            response = self.client.get(f"/sub/{token}")
        self.assertNotIn("secret-detail", "\n".join(logs.output))
        self.assertEqual(500, response.status_code)
        detail = response.json()["detail"]
        self.assertEqual("订阅配置已损坏，请重新发布配置", detail)
        self.assertNotIn("secret-detail", response.text)

        diagnostics = self.client.get(f"/sub/{token}/diagnostics")
        self.assertEqual(500, diagnostics.status_code)
        self.assertNotIn("secret-detail", diagnostics.text)

    def test_validation_errors_are_not_echoed(self):
        token = self._set_yaml("proxies: []\nproxy-groups: []\nrules: []\n")
        response = self.client.get(f"/sub/{token}")
        self.assertEqual(409, response.status_code)
        self.assertNotIn("Proxies 为空", response.text)

    def test_head_returns_headers_without_body(self):
        token = self._set_yaml(VALID_SUBSCRIPTION_YAML)
        with patch.object(api, "build_yaml", wraps=api.build_yaml) as build_yaml:
            head = self.client.head(f"/sub/{token}")
        self.assertEqual(200, head.status_code)
        self.assertEqual(b"", head.content)
        self.assertEqual("1", head.headers.get("x-clash-proxy-count"))
        self.assertEqual("1", head.headers.get("x-clash-proxy-group-count"))
        build_yaml.assert_not_called()

    def test_cache_invalidates_on_republish_and_token_reset(self):
        token = self._set_yaml(VALID_SUBSCRIPTION_YAML)
        first = self.client.get(f"/sub/{token}")
        self.assertEqual(200, first.status_code, first.text)
        with patch.object(api, "build_yaml", wraps=api.build_yaml) as build_yaml:
            cached = self.client.get(f"/sub/{token}")
        self.assertEqual(first.text, cached.text)
        build_yaml.assert_not_called()

        republished = VALID_SUBSCRIPTION_YAML.replace("node-1", "node-renamed")
        self._set_yaml(republished)
        second = self.client.get(f"/sub/{token}")
        self.assertEqual(200, second.status_code, second.text)
        self.assertIn("node-renamed", second.text)
        self.assertNotIn("node-1", second.text)

        new_token = storage.reset_subscription_token(self.user_id)
        self.assertEqual(404, self.client.get(f"/sub/{token}").status_code)
        self.assertEqual(200, self.client.get(f"/sub/{new_token}").status_code)

        storage.set_user_enabled(self.user_id, False)
        self.assertEqual(404, self.client.get(f"/sub/{new_token}").status_code)


if __name__ == "__main__":
    unittest.main()
