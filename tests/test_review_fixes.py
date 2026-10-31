"""复查修复项回归测试：远程抓取 socket 级总超时、CSRF 会话绑定与启动期密钥校验、
管理员初始化开销、规则集数据库实例标识、mihomo 首次校验加锁、500 响应安全头。"""

import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import api
import importers
import mihomo_validator
import ruleset_store
import security
import storage
from test_api_hardening import HardeningTestBase


class _SlowHTTPServer:
    """本地慢速 HTTP 服务：按给定节奏每次只发 1 字节。"""

    def __init__(self, payload: bytes, interval: float = 0.5, fast_prefix: bytes = b""):
        self.payload = payload
        self.interval = interval
        self.fast_prefix = fast_prefix
        self.stop = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.stop.set()
        self.thread.join(5)
        self.listener.close()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _addr = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(2)
                    conn.recv(65536)
                    if self.fast_prefix:
                        conn.sendall(self.fast_prefix)
                    for index in range(len(self.payload)):
                        if self.stop.wait(self.interval):
                            return
                        conn.sendall(self.payload[index:index + 1])
                except OSError:
                    # 客户端到期 shutdown 后这里会出现 BrokenPipe/ConnectionReset，属预期。
                    continue


class ExternalFetchSocketDeadlineTest(unittest.TestCase):
    """问题 1：总耗时上限必须在 socket 层生效，慢速逐字节发送也无法拖住线程。"""

    def setUp(self):
        self.previous = os.environ.get("EXTERNAL_FETCH_DEADLINE_SECONDS")
        os.environ["EXTERNAL_FETCH_DEADLINE_SECONDS"] = "2"

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("EXTERNAL_FETCH_DEADLINE_SECONDS", None)
        else:
            os.environ["EXTERNAL_FETCH_DEADLINE_SECONDS"] = self.previous

    def _fetch(self, port: int):
        url = f"http://127.0.0.1:{port}/sub"
        # 本地地址会被 SSRF 内网拦截；只替换“解析 + 校验”这一步，固定 IP 传输与其余逻辑保持生产实现。
        with patch.object(importers, "_resolve_public_external_url", return_value=(url, ("127.0.0.1",))):
            started = time.monotonic()
            with self.assertRaises(ValueError) as ctx:
                importers.fetch_text_from_external_url(url, timeout=15)
            return time.monotonic() - started, str(ctx.exception)

    def test_slow_response_headers_hit_deadline(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
        with _SlowHTTPServer(payload) as server:
            elapsed, message = self._fetch(server.port)
        self.assertIn("超时", message)
        self.assertGreaterEqual(elapsed, 1.5)
        self.assertLess(elapsed, 4.0)

    def test_slow_body_hits_deadline(self):
        headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\n\r\n"
        with _SlowHTTPServer(b"x" * 100, fast_prefix=headers) as server:
            elapsed, message = self._fetch(server.port)
        self.assertIn("超时", message)
        self.assertGreaterEqual(elapsed, 1.5)
        self.assertLess(elapsed, 4.0)

    def test_eof_delimited_body_cut_by_deadline_is_not_success(self):
        # 无 Content-Length、靠关闭连接结束的响应：被定时器切断后不能当作正常结束返回半截内容。
        headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
        with _SlowHTTPServer(b"y" * 100, fast_prefix=headers) as server:
            elapsed, message = self._fetch(server.port)
        self.assertIn("超时", message)
        self.assertLess(elapsed, 4.0)

    def test_fast_response_still_succeeds(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
        with _SlowHTTPServer(b"", fast_prefix=payload) as server:
            url = f"http://127.0.0.1:{server.port}/sub"
            with patch.object(importers, "_resolve_public_external_url", return_value=(url, ("127.0.0.1",))):
                text, content_type = importers.fetch_text_from_external_url(url, timeout=15)
        self.assertEqual("hello", text)
        self.assertEqual("text/plain", content_type)


class CsrfSessionBindingUnitTest(unittest.TestCase):
    def setUp(self):
        self.previous = os.environ.get("CSRF_SECRET")
        os.environ["CSRF_SECRET"] = "test-secret-that-is-longer-than-thirty-two-characters"

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("CSRF_SECRET", None)
        else:
            os.environ["CSRF_SECRET"] = self.previous

    def test_bound_token_requires_same_binding(self):
        binding_a = security.csrf_session_binding("session-a")
        binding_b = security.csrf_session_binding("session-b")
        self.assertEqual(32, len(binding_a))
        token = security.create_csrf_token("api", binding=binding_a)
        self.assertTrue(security.validate_csrf_token(token, "api", binding=binding_a))
        self.assertFalse(security.validate_csrf_token(token, "api", binding=binding_b))
        self.assertFalse(security.validate_csrf_token(token, "api"))

    def test_unbound_token_does_not_pass_bound_check(self):
        token = security.create_csrf_token("api")
        self.assertTrue(security.validate_csrf_token(token, "api"))
        self.assertFalse(security.validate_csrf_token(token, "api", binding=security.csrf_session_binding("s")))

    def test_ensure_csrf_secret_rejects_placeholder(self):
        os.environ["CSRF_SECRET"] = "replace-with-output-of-openssl-rand-hex-32"
        with self.assertRaises(RuntimeError):
            security.ensure_csrf_secret()
        os.environ["CSRF_SECRET"] = "short"
        with self.assertRaises(RuntimeError):
            security.ensure_csrf_secret()


class CsrfSessionBindingApiTest(HardeningTestBase):
    """问题 3：多标签页换号后，A 的 api token 配 B 的 Cookie 必须 403。"""

    def _session_token(self) -> str:
        response = self.client.get("/api/session")
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.json()["authenticated"])
        return response.json()["csrf_token"]

    def _put_config(self, csrf_token: str):
        return self.client.put(
            "/api/config",
            json={"proxies": [], "custom_rules": [], "custom_rule_providers": {}},
            headers={"Origin": "https://test.local", "X-CSRF-Token": csrf_token},
        )

    def test_token_from_previous_account_rejected_after_switch(self):
        storage.create_user("user-a", "password123")
        storage.create_user("user-b", "password123")
        self._login("user-a")
        token_a = self._session_token()
        # 同一浏览器另一个标签页换号：Cookie 被替换为 B 的会话。
        self._login("user-b")
        rejected = self._put_config(token_a)
        self.assertEqual(403, rejected.status_code, rejected.text)

        token_b = self._session_token()
        accepted = self._put_config(token_b)
        self.assertNotEqual(403, accepted.status_code, accepted.text)
        self.assertNotEqual(401, accepted.status_code, accepted.text)

    def test_login_response_token_bound_to_new_session(self):
        storage.create_user("user-c", "password123")
        response = self.client.post(
            "/api/auth/login",
            json={
                "username": "user-c",
                "password": "password123",
                "csrf_token": security.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
        )
        self.assertEqual(200, response.status_code, response.text)
        accepted = self._put_config(response.json()["csrf_token"])
        self.assertNotIn(accepted.status_code, (401, 403), accepted.text)

    def test_legacy_or_malformed_token_is_403_not_500(self):
        storage.create_user("user-d", "password123")
        self._login("user-d")
        for token in (security.create_csrf_token("api"), "!!!not-base64!!!", "", "YTpiOmM6ZDplOmY"):
            response = self._put_config(token)
            self.assertEqual(403, response.status_code, response.text)

    def test_streamlit_auth_token_unchanged(self):
        # Streamlit 登录/注册表单使用的 auth token 不绑定会话，行为不变。
        token = security.create_csrf_token("auth")
        self.assertTrue(security.validate_csrf_token(token, "auth"))


class CsrfSecretStartupTest(HardeningTestBase):
    """问题 2：CSRF_SECRET 不合规时 FastAPI 启动即失败。"""

    def test_invalid_csrf_secret_fails_startup(self):
        os.environ["CSRF_SECRET"] = "replace-with-output-of-openssl-rand-hex-32"
        with patch.object(api, "start_ruleset_update_worker") as worker:
            with self.assertRaises(RuntimeError) as ctx:
                with TestClient(api.app):
                    pass
        self.assertIn("CSRF_SECRET", str(ctx.exception))
        worker.assert_not_called()

    def test_valid_csrf_secret_starts(self):
        with patch.object(api, "start_ruleset_update_worker"):
            with TestClient(api.app) as client:
                self.assertEqual(200, client.get("/api/session").status_code)


class AdminEnvInitTest(HardeningTestBase):
    """问题 4：管理员已存在时不做 PBKDF2 比对，提示每进程只打一次。"""

    def test_existing_admin_skips_password_hash_and_logs_once(self):
        storage.create_user("root-x", "first-password", is_admin=True)
        os.environ["ADMIN_USERNAME"] = "root-x"
        os.environ["ADMIN_PASSWORD"] = "second-password"
        with patch.object(storage, "verify_password", side_effect=AssertionError("不应调用")):
            with self.assertLogs("storage", level="INFO") as logs:
                storage.ensure_admin_from_env()
                storage.ensure_admin_from_env()
        notices = [line for line in logs.output if "忽略 ADMIN_PASSWORD" in line]
        self.assertEqual(1, len(notices))
        self.assertIsNotNone(storage.authenticate_user("root-x", "first-password"))


class RulesetDbInstanceTest(HardeningTestBase):
    """问题 5：规则集目录属于另一个数据库实例时，不做孤儿目录清理。"""

    def setUp(self):
        super().setUp()
        self.ruleset_dir = Path(os.environ["RULESET_DIR"])
        storage.create_user("owner", "password123")
        self.orphan = self.ruleset_dir / "users" / "4242"
        self.orphan.mkdir(parents=True)
        (self.orphan / "kept.yaml").write_bytes(b"kept")
        self.marker = self.ruleset_dir / ruleset_store.RULESET_DB_INSTANCE_MARKER

    def _tombstone(self):
        tombstone = self.ruleset_dir / ".trash" / ("4343-" + "e" * 32)
        tombstone.mkdir(parents=True)
        (tombstone / "deleted.yaml").write_bytes(b"deleted")
        return tombstone

    def test_missing_marker_is_claimed_and_cleanup_skipped_once(self):
        tombstone = self._tombstone()
        self.assertEqual([], ruleset_store._retry_ruleset_tombstones())
        self.assertTrue((self.orphan / "kept.yaml").is_file())
        self.assertFalse(tombstone.exists())
        self.assertEqual(storage.get_db_instance_id(), self.marker.read_text(encoding="utf-8").strip())
        self.assertEqual([], ruleset_store._retry_ruleset_tombstones())
        self.assertFalse(self.orphan.exists())

    def test_mismatched_marker_skips_orphan_cleanup_but_handles_tombstones(self):
        self.marker.write_text("another-database-instance\n", encoding="utf-8")
        tombstone = self._tombstone()
        with self.assertLogs("ruleset_store", level="ERROR"):
            self.assertEqual([], ruleset_store._retry_ruleset_tombstones())
        self.assertTrue((self.orphan / "kept.yaml").is_file())
        self.assertFalse(tombstone.exists())
        self.assertEqual("another-database-instance", self.marker.read_text(encoding="utf-8").strip())

    def test_db_instance_id_is_stable(self):
        first = storage.get_db_instance_id()
        storage.init_db()
        self.assertEqual(first, storage.get_db_instance_id())


class MihomoFirstRunLockTest(unittest.TestCase):
    """问题 6：MIHOMO_HOME 缺 geodata 时串行化并放宽超时；已有 geodata 时保持原逻辑。"""

    CONFIG = "geodata-mode: false\nrules:\n- GEOIP,CN,DIRECT\n- GEOSITE,cn,DIRECT\n- MATCH,DIRECT\n"

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "MIHOMO_VALIDATE_ENABLED": "true",
                "MIHOMO_HOME": self.tmpdir.name,
                "MIHOMO_BINARY": "mihomo-test",
            },
        )
        self.env.start()
        os.environ.pop("MIHOMO_FIRST_RUN_TIMEOUT", None)
        self.which = patch.object(mihomo_validator.shutil, "which", return_value="/usr/bin/mihomo-test")
        self.which.start()

    def tearDown(self):
        self.which.stop()
        self.env.stop()
        self.tmpdir.cleanup()

    def _run(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")
        lock_calls = []
        real_lock = mihomo_validator._geodata_download_lock

        def recording_lock(home_dir):
            lock_calls.append(home_dir)
            return real_lock(home_dir)

        with patch.object(mihomo_validator.subprocess, "run", return_value=completed) as run, patch.object(
            mihomo_validator, "_geodata_download_lock", side_effect=recording_lock
        ):
            result = mihomo_validator.validate_with_mihomo(self.CONFIG)
        return result, run, lock_calls

    def test_missing_geodata_uses_lock_and_first_run_timeout(self):
        result, run, lock_calls = self._run()
        self.assertTrue(result.ok)
        self.assertEqual(60, run.call_args.kwargs["timeout"])
        self.assertEqual([self.tmpdir.name], lock_calls)

    def test_first_run_timeout_env_override(self):
        os.environ["MIHOMO_FIRST_RUN_TIMEOUT"] = "90"
        _result, run, _lock_calls = self._run()
        self.assertEqual(90, run.call_args.kwargs["timeout"])

    def test_present_geodata_keeps_default_timeout_without_lock(self):
        for name in ("geoip.metadb", "GeoSite.dat"):
            Path(self.tmpdir.name, name).write_bytes(b"data")
        result, run, lock_calls = self._run()
        self.assertTrue(result.ok)
        self.assertEqual(10, run.call_args.kwargs["timeout"])
        self.assertEqual([], lock_calls)

    def test_geodata_mode_requires_geoip_dat(self):
        # geodata-mode: true 时 GEOIP 用 GeoIP.dat，仅有 MMDB 仍视为缺失。
        for name in ("Country.mmdb", "GeoSite.dat"):
            Path(self.tmpdir.name, name).write_bytes(b"data")
        config = self.CONFIG.replace("geodata-mode: false", "geodata-mode: true")
        self.assertTrue(mihomo_validator._required_geodata_missing(self.tmpdir.name, config))
        self.assertFalse(mihomo_validator._required_geodata_missing(self.tmpdir.name, self.CONFIG))

    def test_first_run_timeout_reported(self):
        with patch.object(
            mihomo_validator.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="mihomo", timeout=60)
        ):
            result = mihomo_validator.validate_with_mihomo(self.CONFIG)
        self.assertEqual("timeout", result.status)
        self.assertIn("60", result.message)


class UnhandledErrorSecurityHeadersTest(HardeningTestBase):
    """问题 7：未捕获异常的 500 响应同样带安全头（含 HTTPS 下的 HSTS）。"""

    def _assert_security_headers(self, response):
        for name in api._SECURITY_HEADERS:
            self.assertIn(name, response.headers)
        self.assertEqual("max-age=31536000", response.headers.get("strict-transport-security"))

    def test_non_api_500_has_security_headers(self):
        client = TestClient(api.app, raise_server_exceptions=False)
        try:
            with patch.object(api, "health_snapshot", side_effect=RuntimeError("boom")):
                response = client.get("/health")
        finally:
            client.close()
        self.assertEqual(500, response.status_code)
        self.assertEqual({"detail": "Internal Server Error"}, response.json())
        self._assert_security_headers(response)

    def test_api_500_has_security_headers(self):
        client = TestClient(api.app, raise_server_exceptions=False)
        try:
            with patch.object(api, "get_user_by_auth_session", side_effect=RuntimeError("boom")):
                response = client.get("/api/session")
        finally:
            client.close()
        self.assertEqual(500, response.status_code)
        self.assertEqual({"ok": False, "error": "服务器内部错误"}, response.json())
        self._assert_security_headers(response)


if __name__ == "__main__":
    unittest.main()
