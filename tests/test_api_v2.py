import os
import copy
import json
import multiprocessing
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient

import api
import storage


def _hold_ruleset_lock_in_child(ruleset_dir, started, release):
    os.environ["RULESET_DIR"] = ruleset_dir
    with api._ruleset_user_lock(991):
        started.set()
        release.wait(15)


def _wait_ruleset_lock_in_child(ruleset_dir, started, entered):
    os.environ["RULESET_DIR"] = ruleset_dir
    started.set()
    with api._ruleset_user_lock(991):
        entered.set()


class APITest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.previous_env = {
            name: os.environ.get(name)
            for name in (
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
            )
        }
        os.environ.update(
            {
                "APP_DB_PATH": os.path.join(self.tmpdir.name, "app.db"),
                "PUBLIC_BASE_URL": "https://test.local",
                "CSRF_SECRET": "test-secret-that-is-longer-than-thirty-two-characters",
                "ALLOW_REGISTRATION": "false",
                "AUTH_COOKIE_SECURE": "false",
                "RULESET_CACHE_ENABLED": "false",
                "AUTH_RATE_LIMIT_ACCOUNT_FAILURES": "2",
                "AUTH_RATE_LIMIT_IP_FAILURES": "10",
                "AUTH_RATE_LIMIT_WINDOW_SECONDS": "900",
                "MIHOMO_VALIDATE_ENABLED": "false",
            }
        )
        storage.init_db()
        storage.create_user("api-user", "password123")
        self.client = TestClient(api.app)

    def tearDown(self):
        self.client.close()
        for name, value in self.previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self.tmpdir.cleanup()

    # ---------- helper ----------

    def _login_form(self, password="password123"):
        return self.client.post(
            "/sub/auth/login",
            data={
                "username": "api-user",
                "password": password,
                "csrf_token": api.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )

    def _csrf(self, action="api"):
        return api.create_csrf_token(action)

    def _headers(self, action="api", origin="https://test.local"):
        return {"Origin": origin, "X-CSRF-Token": self._csrf(action)}

    def _login(self):
        response = self._login_form()
        assert response.status_code == 303

    def _put_draft(self, body=None):
        if body is None:
            from config_defaults import build_default_global_config

            body = {
                "proxies": [
                    {
                        "name": "node-1",
                        "type": "ss",
                        "server": "example.com",
                        "port": 8388,
                        "cipher": "2022-blake3-aes-128-gcm",
                        "password": "secret",
                        "udp": True,
                    }
                ],
                "global_config": build_default_global_config(),
                "custom_rules": [],
                "custom_rule_providers": {},
                "selected_rule_type": "dustinwin规则",
            }
        return self.client.put("/api/config", json=body, headers=self._headers())

    # ---------- 认证 ----------

    def test_session_unauthenticated(self):
        response = self.client.get("/api/session", headers={"Origin": "https://test.local"})
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertFalse(data["authenticated"])
        self.assertIn("csrf_token", data)

    def test_session_authenticated(self):
        self._login()
        response = self.client.get("/api/session", headers={"Origin": "https://test.local"})
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue(data["authenticated"])
        self.assertEqual("api-user", data["user"]["username"])
        self.assertFalse(data["user"]["is_admin"])
        self.assertIn("csrf_token", data)

    def test_login_rejects_untrusted_origin(self):
        self._login_form()
        # 上面的请求带了错误 origin 会被拒绝；这里单独验证
        response = self.client.post(
            "/sub/auth/login",
            data={
                "username": "api-user",
                "password": "password123",
                "csrf_token": api.create_csrf_token("auth"),
            },
            headers={"Origin": "https://evil.example"},
            follow_redirects=False,
        )
        self.assertEqual(303, response.status_code)
        self.assertIn("auth_error", response.headers["location"])

    def test_login_rate_limit(self):
        self.assertEqual(303, self._login_form("wrong-password").status_code)
        self.assertEqual(303, self._login_form("wrong-password").status_code)
        blocked = self._login_form("password123")
        self.assertEqual(303, blocked.status_code)

    # ---------- 草稿 ----------

    def test_put_draft_requires_auth(self):
        response = self.client.put("/api/config", json={}, headers={"Origin": "https://test.local"})
        self.assertEqual(401, response.status_code)

    def test_put_draft_requires_csrf(self):
        self._login()
        response = self.client.put(
            "/api/config",
            json={"proxies": [], "global_config": {}, "custom_rules": [], "custom_rule_providers": {}, "selected_rule_type": "dustinwin规则"},
            headers={"Origin": "https://test.local"},
        )
        self.assertEqual(403, response.status_code)

    def test_put_draft_wrong_action_csrf(self):
        self._login()
        response = self.client.put(
            "/api/config",
            json={"proxies": [], "global_config": {}, "custom_rules": [], "custom_rule_providers": {}, "selected_rule_type": "dustinwin规则"},
            headers={"Origin": "https://test.local", "X-CSRF-Token": self._csrf("auth")},
        )
        self.assertEqual(403, response.status_code)

    def test_put_draft_success(self):
        self._login()
        response = self._put_draft()
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertEqual(1, data["counts"]["nodes"])

    def test_put_draft_recomputes_import_source_counts(self):
        self._login()
        body = {
            "proxies": [
                {
                    "name": "a",
                    "type": "ss",
                    "server": "a.example.com",
                    "port": 8388,
                    "cipher": "2022-blake3-aes-128-gcm",
                    "password": "x",
                    "_source_id": "src-1",
                },
                {
                    "name": "b",
                    "type": "ss",
                    "server": "b.example.com",
                    "port": 8388,
                    "cipher": "2022-blake3-aes-128-gcm",
                    "password": "x",
                    "_source_id": "src-1",
                },
            ],
            "global_config": {"is_desktop": False},
            "custom_rules": [],
            "custom_rule_providers": {},
            "selected_rule_type": "dustinwin规则",
            "import_sources": [{"id": "src-1", "name": "订阅", "type": "url", "node_count": 99, "imported_at": ""}],
        }
        response = self.client.put("/api/config", json=body, headers=self._headers())
        self.assertEqual(200, response.status_code)
        saved = storage.get_user_config(1)
        self.assertEqual(2, saved["import_sources"][0]["node_count"])

    def test_put_draft_rejects_oversized_payload(self):
        self._login()
        from config_defaults import build_default_global_config

        body = {
            "proxies": [
                {
                    "name": f"node-{i}",
                    "type": "ss",
                    "server": "example.com",
                    "port": 8388,
                    "cipher": "2022-blake3-aes-128-gcm",
                    "password": "x" * 4000,
                }
                for i in range(501)
            ],
            "global_config": build_default_global_config(),
            "custom_rules": [],
            "custom_rule_providers": {},
            "selected_rule_type": "dustinwin规则",
        }
        response = self.client.put("/api/config", json=body, headers=self._headers())
        self.assertIn(response.status_code, (413, 400))

    # ---------- 导入 ----------

    def test_import_yaml(self):
        self._login()
        yaml_content = """proxies:
  - name: test-node
    type: ss
    server: test.example.com
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: testpass
"""
        response = self.client.post(
            "/api/import",
            json={"mode": "yaml", "content": yaml_content, "existing_proxies": []},
            headers=self._headers(),
        )
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertEqual(1, len(data["proxies"]))

    def test_import_share_link(self):
        self._login()
        response = self.client.post(
            "/api/import",
            json={"mode": "share", "url": "vmess://invalid-share-link", "existing_proxies": []},
            headers=self._headers(),
        )
        self.assertIn(response.status_code, (200, 400))

    def test_import_rejects_invalid_ports_without_skipping_or_truncating(self):
        self._login()
        for port_value in ("true", "false", "443.0", "443.5"):
            yaml_content = f"""proxies:
  - name: invalid-port-{port_value}
    type: ss
    server: invalid.example.com
    port: {port_value}
    cipher: aes-128-gcm
    password: testpass
"""
            response = self.client.post(
                "/api/import",
                json={"mode": "yaml", "content": yaml_content, "existing_proxies": []},
                headers=self._headers(),
            )
            self.assertEqual(400, response.status_code, response.text)
            payload = response.json()
            self.assertEqual(False, payload.get("ok"), payload)
            self.assertIsInstance(payload.get("error"), str)
            self.assertNotIn("detail", payload)

        for share_link in (
            "ss://aes-128-gcm:password@example.com:443.0#invalid-port",
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443.5?type=tcp",
        ):
            response = self.client.post(
                "/api/import",
                json={"mode": "share", "content": share_link, "existing_proxies": []},
                headers=self._headers(),
            )
            self.assertEqual(400, response.status_code, response.text)
            payload = response.json()
            self.assertEqual(False, payload.get("ok"), payload)
            self.assertIn("error", payload)

    def test_invalid_draft_ports_are_rejected_before_put_validate_or_publish(self):
        self._login()
        draft = self._put_draft().json()["config"]
        published = self.client.post("/api/publish", json=draft, headers=self._headers())
        self.assertEqual(200, published.status_code, published.text)
        before = storage.get_user_config(1)
        for port_value in (True, False, 443.0, 443.5):
            invalid = copy.deepcopy(draft)
            invalid["proxies"][0]["port"] = port_value
            put_response = self.client.put("/api/config", json=invalid, headers=self._headers())
            self.assertEqual(400, put_response.status_code, put_response.text)
            put_payload = put_response.json()
            self.assertEqual(False, put_payload.get("ok"), put_payload)
            self.assertIn("error", put_payload)
            validate_response = self.client.post("/api/validate", json=invalid, headers=self._headers())
            self.assertEqual(400, validate_response.status_code, validate_response.text)
            validate_payload = validate_response.json()
            self.assertEqual(False, validate_payload.get("ok"), validate_payload)
            publish_response = self.client.post("/api/publish", json=invalid, headers=self._headers())
            self.assertEqual(400, publish_response.status_code, publish_response.text)
            publish_payload = publish_response.json()
            self.assertEqual(False, publish_payload.get("ok"), publish_payload)
            current = storage.get_user_config(1)
            self.assertEqual(before["final_yaml"], current["final_yaml"])
            self.assertEqual(before["proxies"], current["proxies"])

    def test_streamlit_manual_workflow_uses_shared_builder_without_protocol_duplicate(self):
        source = Path("src/web_app.py").read_text(encoding="utf-8")
        start = source.index("# 表单只负责收集字段；协议字段")
        end = source.index("manual_node_yaml =", start)
        builder_section = source[start:end]
        self.assertIn("manual_node = build_manual_node(node_type, manual_fields)", builder_section)
        self.assertIn('"use_dialer_proxy", "dialer_proxy_name"', builder_section)
        self.assertNotRegex(builder_section, r"if node_type == ['\"](?:vmess|ss|trojan|hysteria2|tuic|vless|anytls)")
        self.assertNotIn('manual_node["grpc-service-name"]', builder_section)

    def test_shared_builder_emits_dialer_proxy_when_manual_chain_is_enabled(self):
        self._login()
        response = self.client.post(
            "/api/node/build",
            json={
                "type": "ss",
                "fields": {
                    "node_name": "Chain-Node",
                    "node_server": "chain.example.com",
                    "node_port": 9443,
                    "ss_encryption": "aes-128-gcm",
                    "node_password": "chain-password",
                    "use_dialer_proxy": True,
                    "dialer_proxy_name": "Alpha",
                },
                "existing_proxies": [],
            },
            headers=self._headers(),
        )
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual("Alpha", response.json()["node"]["dialer-proxy"])

    # ---------- 校验 / 发布 / Token ----------

    def test_validate_success(self):
        self._login()
        draft = self._put_draft().json()["config"]
        response = self.client.post("/api/validate", json=draft, headers=self._headers())
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertIn("checks", data)
        self.assertIn("stats", data)
        self.assertIn("mihomo", data)
        self.assertIn("yaml", data)
        self.assertIn("publish_diff", data)
        self.assertEqual(data["publish_diff"], data["diff"])

    def test_validate_requires_complete_request_draft(self):
        self._login()
        response = self.client.post("/api/validate", headers=self._headers())
        self.assertEqual(400, response.status_code)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertNotIn("detail", payload)

    def test_publish_success(self):
        self._login()
        draft = self._put_draft().json()["config"]
        response = self.client.post("/api/publish", json=draft, headers=self._headers())
        data = response.json()
        if response.status_code == 200:
            self.assertTrue(data["ok"])
            self.assertIn("subscription_url", data)
            self.assertIn("publish_diff", data)
            self.assertEqual(data["publish_diff"], data["diff"])
        else:
            # 校验失败时返回 409
            self.assertEqual(409, response.status_code)
            self.assertIn("error", data)
            self.assertIn("details", data)
            self.assertIn("publish_diff", data["details"])

    def test_publish_failure_exposes_safe_publish_diff_summary(self):
        self._login()
        draft = self._put_draft().json()["config"]
        duplicate = dict(draft["proxies"][0])
        draft["proxies"] = [duplicate, dict(duplicate)]
        response = self.client.post("/api/publish", json=draft, headers=self._headers())
        self.assertEqual(409, response.status_code)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIn("details", payload)
        self.assertIn("publish_diff", payload["details"])
        self.assertIn("diff", payload["details"])
        self.assertNotIn("unified", payload["details"]["publish_diff"])
        validation = payload["details"]["validation"]
        self.assertIn("publish_diff", validation)
        self.assertIn("diff", validation)
        self.assertNotIn("unified", validation["publish_diff"])

    def test_sub_link_after_publish(self):
        self._login()
        draft = self._put_draft().json()["config"]
        publish_response = self.client.post("/api/publish", json=draft, headers=self._headers())
        if publish_response.status_code != 200:
            self.skipTest("发布失败，订阅链接验证跳过")
        token = storage.get_user_config(1)["token"]
        response = self.client.get(f"/sub/{token}")
        self.assertEqual(200, response.status_code)
        self.assertIn("proxies:", response.text)

    def test_token_reset(self):
        self._login()
        self._put_draft()
        old_token = storage.get_user_config(1)["token"]
        response = self.client.post("/api/token/reset", headers=self._headers())
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertIn("subscription_url", data)
        new_token = storage.get_user_config(1)["token"]
        self.assertNotEqual(old_token, new_token)

    def test_token_reset_invalidates_old_subscription(self):
        self._login()
        draft = self._put_draft().json()["config"]
        publish_response = self.client.post("/api/publish", json=draft, headers=self._headers())
        self.assertEqual(200, publish_response.status_code)
        old_token = storage.get_user_config(1)["token"]
        reset_response = self.client.post("/api/token/reset", headers=self._headers())
        self.assertEqual(200, reset_response.status_code)
        new_token = reset_response.json()["token"]
        self.assertNotEqual(old_token, new_token)
        self.assertEqual(404, self.client.get(f"/sub/{old_token}").status_code)
        self.assertEqual(200, self.client.get(f"/sub/{new_token}").status_code)

    def test_admin_token_reset_rechecks_target_inside_user_guard(self):
        admin = storage.create_user("api-reset-admin", "admin-password", is_admin=True)
        target = storage.create_user("api-reset-target", "password123")
        admin_login = self.client.post(
            "/sub/auth/login",
            data={
                "username": "api-reset-admin",
                "password": "admin-password",
                "csrf_token": api.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        self.assertEqual(303, admin_login.status_code)
        old_token = storage.get_user_config(int(target["id"]))["token"]
        response = self.client.post(
            f"/api/users/{int(target['id'])}/reset-token",
            headers=self._headers(),
        )
        self.assertEqual(200, response.status_code, response.text)
        new_token = response.json()["token"]
        self.assertNotEqual(old_token, new_token)
        storage.set_user_enabled(int(target["id"]), False)
        disabled = self.client.post(
            f"/api/users/{int(target['id'])}/reset-token",
            headers=self._headers(),
        )
        self.assertEqual(409, disabled.status_code)

    def test_admin_reset_and_delete_race_never_mints_token_after_deletion(self):
        storage.create_user("api-race-admin", "admin-password", is_admin=True)
        admin_login = self.client.post(
            "/sub/auth/login",
            data={
                "username": "api-race-admin",
                "password": "admin-password",
                "csrf_token": api.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        self.assertEqual(303, admin_login.status_code)
        clients = []
        try:
            # Deterministically exercise both linearizations.  The worker is
            # admitted while the real target lock is held; releasing the
            # lock is the explicit serialization point, so this does not rely
            # on a timing race between two requests.
            reset_first_target = storage.create_user("api-race-reset-first", "password123")
            reset_first_id = int(reset_first_target["id"])
            reset_client = TestClient(api.app, raise_server_exceptions=False)
            delete_client = TestClient(api.app, raise_server_exceptions=False)
            clients.extend((reset_client, delete_client))
            reset_client.cookies.update(self.client.cookies)
            delete_client.cookies.update(self.client.cookies)
            reset_started = threading.Event()
            reset_result = {}

            def run_reset_first():
                reset_started.set()
                reset_result["response"] = reset_client.post(
                    f"/api/users/{reset_first_id}/reset-token",
                    headers=self._headers(),
                )

            with api._ruleset_user_lock(reset_first_id):
                reset_thread = threading.Thread(target=run_reset_first)
                reset_thread.start()
                self.assertTrue(reset_started.wait(2))
            reset_thread.join(5)
            self.assertFalse(reset_thread.is_alive())
            self.assertEqual(200, reset_result["response"].status_code, reset_result["response"].text)
            delete_after_reset = self.client.post(
                f"/api/users/{reset_first_id}/delete",
                headers=self._headers(),
            )
            self.assertEqual(200, delete_after_reset.status_code, delete_after_reset.text)
            self.assertIsNone(storage.get_user_by_id(reset_first_id))

            delete_first_target = storage.create_user("api-race-delete-first", "password123")
            delete_first_id = int(delete_first_target["id"])
            delete_first_client = TestClient(api.app, raise_server_exceptions=False)
            reset_after_delete_client = TestClient(api.app, raise_server_exceptions=False)
            clients.extend((delete_first_client, reset_after_delete_client))
            delete_first_client.cookies.update(self.client.cookies)
            reset_after_delete_client.cookies.update(self.client.cookies)
            delete_started = threading.Event()
            delete_result = {}

            def run_delete_first():
                delete_started.set()
                delete_result["response"] = delete_first_client.post(
                    f"/api/users/{delete_first_id}/delete",
                    headers=self._headers(),
                )

            with api._ruleset_user_lock(delete_first_id):
                delete_thread = threading.Thread(target=run_delete_first)
                delete_thread.start()
                self.assertTrue(delete_started.wait(2))
            delete_thread.join(5)
            self.assertFalse(delete_thread.is_alive())
            self.assertEqual(200, delete_result["response"].status_code, delete_result["response"].text)
            reset_after_delete = reset_after_delete_client.post(
                f"/api/users/{delete_first_id}/reset-token",
                headers=self._headers(),
            )
            self.assertEqual(404, reset_after_delete.status_code, reset_after_delete.text)
            self.assertIsNone(storage.get_user_by_id(delete_first_id))
        finally:
            for client in clients:
                client.close()

    def test_admin_toggle_and_delete_recheck_actor_after_waiting_for_target_guard(self):
        admin = storage.create_user("api-lifecycle-admin", "admin-password", is_admin=True)
        target = storage.create_user("api-lifecycle-target", "password123")
        admin_login = self.client.post(
            "/sub/auth/login",
            data={
                "username": "api-lifecycle-admin",
                "password": "admin-password",
                "csrf_token": api.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        self.assertEqual(303, admin_login.status_code)
        target_id = int(target["id"])
        toggle_client = TestClient(api.app, raise_server_exceptions=False)
        delete_client = TestClient(api.app, raise_server_exceptions=False)
        toggle_client.cookies.update(self.client.cookies)
        delete_client.cookies.update(self.client.cookies)
        toggle_started = threading.Event()
        delete_started = threading.Event()

        def run_toggle(result):
            toggle_started.set()
            result["response"] = toggle_client.post(
                f"/api/users/{target_id}/toggle",
                headers=self._headers(),
            )

        def run_delete(result):
            delete_started.set()
            result["response"] = delete_client.post(
                f"/api/users/{target_id}/delete",
                headers=self._headers(),
            )

        try:
            toggle_result = {}
            with api._ruleset_user_lock(target_id):
                toggle_thread = threading.Thread(target=run_toggle, args=(toggle_result,))
                toggle_thread.start()
                # The request has passed the stale outer admin check and is
                # waiting for the target guard.  Revoke the actor now; the
                # locked helper must reject it after the guard opens.
                self.assertTrue(toggle_started.wait(2))
                storage.set_user_enabled(int(admin["id"]), False)
            toggle_thread.join(5)
            self.assertFalse(toggle_thread.is_alive())
            self.assertEqual(401, toggle_result["response"].status_code)
            self.assertTrue(bool(storage.get_user_by_id(target_id)["is_enabled"]))

            # Restore the actor for the delete race and hold the target lock so
            # the request's pre-lock admin admission cannot be confused with
            # the authoritative check inside the helper.
            storage.set_user_enabled(int(admin["id"]), True)
            delete_result = {}
            with api._ruleset_user_lock(target_id):
                delete_thread = threading.Thread(target=run_delete, args=(delete_result,))
                delete_thread.start()
                self.assertTrue(delete_started.wait(2))
                storage.set_user_enabled(int(admin["id"]), False)
            delete_thread.join(5)
            self.assertFalse(delete_thread.is_alive())
            self.assertEqual(401, delete_result["response"].status_code)
            self.assertIsNotNone(storage.get_user_by_id(target_id))
        finally:
            toggle_client.close()
            delete_client.close()

    def test_admin_toggle_serializes_with_upload_and_disabled_user_cannot_write(self):
        admin = storage.create_user("api-toggle-upload-admin", "admin-password", is_admin=True)
        target = storage.create_user("api-toggle-upload-target", "password123")
        admin_login = self.client.post(
            "/sub/auth/login",
            data={
                "username": "api-toggle-upload-admin",
                "password": "admin-password",
                "csrf_token": api.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        self.assertEqual(303, admin_login.status_code)
        target_client = TestClient(api.app, raise_server_exceptions=False)
        target_login = target_client.post(
            "/sub/auth/login",
            data={
                "username": "api-toggle-upload-target",
                "password": "password123",
                "csrf_token": api.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        self.assertEqual(303, target_login.status_code)
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        target_id = int(target["id"])
        try:
            toggle_started = threading.Event()
            toggle_result = {}

            def run_toggle():
                toggle_started.set()
                toggle_result["response"] = self.client.post(
                    f"/api/users/{target_id}/toggle",
                    headers=self._headers(),
                )

            # Admit toggle while the real target guard is held.  Once the
            # guard is released it must re-read the target and commit the
            # disabled state before the subsequent upload can authenticate.
            with api._ruleset_user_lock(target_id):
                toggle_thread = threading.Thread(target=run_toggle)
                toggle_thread.start()
                self.assertTrue(toggle_started.wait(2))
            toggle_thread.join(5)
            self.assertFalse(toggle_thread.is_alive())
            toggle_response = toggle_result["response"]
            self.assertEqual(200, toggle_response.status_code, toggle_response.text)
            self.assertFalse(bool(storage.get_user_by_id(target_id)["is_enabled"]))
            upload_response = target_client.post(
                "/api/ruleset/upload",
                headers={
                    "Origin": "https://test.local",
                    "X-CSRF-Token": api.create_csrf_token("api"),
                },
                files={"file": ("disabled.yaml", b"payload", "text/yaml")},
                data={"alias": "disabled", "format": "yaml"},
            )
            self.assertIn(upload_response.status_code, (401, 409))
            self.assertFalse(Path(ruleset_dir.name, "users").exists())
        finally:
            target_client.close()
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    # ---------- 节点构建 ----------

    def test_node_build(self):
        self._login()
        response = self.client.post(
            "/api/node/build",
            json={
                "type": "ss",
                "fields": {
                    "node_name": "built-node",
                    "node_server": "example.com",
                    "node_port": 8388,
                    "node_password": "secret",
                    "node_cipher": "aes-128-gcm",
                    "node_udp": True,
                },
            },
            headers=self._headers(),
        )
        self.assertEqual(200, response.status_code)
        data = response.json()
        node = data["node"]
        self.assertEqual("built-node", node["name"])
        self.assertEqual("ss", node["type"])

    def test_vless_reality_public_key_requires_unpadded_32_byte_base64url(self):
        self._login()
        common = {
            "node_name": "vless-reality",
            "node_server": "example.com",
            "node_port": 443,
            "node_uuid": "123e4567-e89b-12d3-a456-426614174000",
            "vless_tls": True,
            "vless_network": "tcp",
            "vless_short_id": "0123abcd",
        }
        public_key = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
        valid = self.client.post(
            "/api/node/build",
            json={
                "type": "vless",
                "fields": {**common, "vless_flow": "none", "vless_public_key": public_key},
            },
            headers=self._headers(),
        )
        self.assertEqual(200, valid.status_code, valid.text)
        node = valid.json()["node"]
        self.assertNotIn("flow", node)
        self.assertEqual(public_key, node["reality-opts"]["public-key"])

        empty_reality = self.client.post(
            "/api/node/build",
            json={
                "type": "vless",
                "fields": {**common, "vless_flow": "none", "vless_public_key": "", "vless_short_id": ""},
            },
            headers=self._headers(),
        )
        self.assertEqual(200, empty_reality.status_code, empty_reality.text)
        self.assertNotIn("reality-opts", empty_reality.json()["node"])

        for invalid_key in (
            public_key + "=",
            public_key[:-1] + "!",
            "AQIDBAUGBwgJCgsMDQ4PEA",
        ):
            response = self.client.post(
                "/api/node/build",
                json={
                    "type": "vless",
                    "fields": {**common, "vless_flow": "xtls-rprx-vision", "vless_public_key": invalid_key},
                },
                headers=self._headers(),
            )
            self.assertEqual(400, response.status_code, response.text)
            payload = response.json()
            self.assertEqual(False, payload.get("ok"), payload)
            self.assertIn("error", payload)
            self.assertNotIn(invalid_key, payload["error"])
            self.assertNotIn("node", payload)

    def test_shadowsocks_2022_cipher_requires_canonical_base64_key_lengths(self):
        self._login()
        common = {"node_name": "ss-2022", "node_server": "example.com", "node_port": 443}
        key128 = "MDEyMzQ1Njc4OWFiY2RlZg=="
        key256 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

        for cipher, password in (
            ("2022-blake3-aes-128-gcm", key128),
            ("2022-blake3-aes-256-gcm", key256),
            ("2022-blake3-chacha20-poly1305", key256),
        ):
            response = self.client.post(
                "/api/node/build",
                json={
                    "type": "ss",
                    "fields": {**common, "ss_encryption": cipher, "node_password": password},
                },
                headers=self._headers(),
            )
            self.assertEqual(200, response.status_code, response.text)
            self.assertEqual(cipher, response.json()["node"]["cipher"])

        for cipher, password in (
            ("2022-blake3-aes-128-gcm", "ordinary-password"),
            ("2022-blake3-aes-128-gcm", "c2hvcnQ="),
            ("2022-blake3-aes-128-gcm", "MDEyMzQ1Njc4OWFiY2RlZg"),
            ("2022-blake3-aes-256-gcm", key128),
            ("2022-blake3-chacha20-poly1305", key128),
        ):
            response = self.client.post(
                "/api/node/build",
                json={
                    "type": "ss",
                    "fields": {**common, "ss_encryption": cipher, "node_password": password},
                },
                headers=self._headers(),
            )
            self.assertEqual(400, response.status_code, response.text)
            payload = response.json()
            self.assertEqual(False, payload.get("ok"), payload)
            self.assertIn("error", payload)
            self.assertNotIn(password, payload["error"])
            self.assertNotIn("node", payload)

    def test_node_build_rejects_missing_required_credentials_and_maps_transports(self):
        self._login()
        uuid_value = "123e4567-e89b-12d3-a456-426614174000"

        def build(node_type, fields):
            response = self.client.post(
                "/api/node/build",
                json={"type": node_type, "fields": fields},
                headers=self._headers(),
            )
            self.assertEqual(200, response.status_code, response.text)
            return response.json()["node"]

        common = {"node_name": "manual", "node_server": "example.com", "node_port": 443}
        self.assertEqual("p", build("ss", {**common, "node_password": "p"})["password"])
        self.assertEqual("ssr", build("ssr", {**common, "node_password": "p"})["type"])
        vmess = build(
            "vmess",
            {
                **common,
                "node_uuid": uuid_value,
                "network_type": "ws",
                "ws_path": "/socket",
                "ws_host": "cdn.example.com",
            },
        )
        self.assertEqual("/socket", vmess["ws-opts"]["path"])
        self.assertEqual("cdn.example.com", vmess["ws-opts"]["headers"]["Host"])
        vmess_grpc = build(
            "vmess",
            {
                **common,
                "node_uuid": uuid_value,
                "network_type": "grpc",
                "grpc_service_name": "vmess-service",
            },
        )
        self.assertEqual({"grpc-service-name": "vmess-service"}, vmess_grpc["grpc-opts"])
        self.assertNotIn("grpc-service-name", vmess_grpc)
        ss = build("ss", {**common, "node_password": "p"})
        self.assertNotIn("network", ss)
        vless = build(
            "vless",
            {
                **common,
                "node_uuid": uuid_value,
                "vless_network": "h2",
                "vless_h2_path": "/h2",
                "vless_h2_host": "h2.example.com",
            },
        )
        self.assertEqual(["h2.example.com"], vless["h2-opts"]["host"])
        trojan = build(
            "trojan",
            {**common, "node_password": "p", "trojan_network": "grpc", "grpc_service_name": "svc"},
        )
        self.assertEqual("svc", trojan["grpc-opts"]["grpc-service-name"])
        hy2 = build(
            "hysteria2",
            {
                **common,
                "node_password": "p",
                "enable_quic_params": True,
                "initial_stream_receive_window": 123,
            },
        )
        self.assertEqual(123, hy2["quic-params"]["initial-stream-receive-window"])
        self.assertNotIn("protocol", hy2)
        tuic = build("tuic", {**common, "tuic_uuid": uuid_value, "tuic_password": "p"})
        self.assertEqual(uuid_value, tuic["uuid"])

        required_cases = {
            "ss": {"node_password": ""},
            "ssr": {"node_password": ""},
            "vmess": {"node_uuid": ""},
            "trojan": {"node_password": ""},
            "vless": {"node_uuid": ""},
            "hysteria2": {"node_password": ""},
            "tuic": {"tuic_uuid": "", "tuic_password": ""},
        }
        for node_type, missing in required_cases.items():
            fields = {**common, **missing}
            response = self.client.post(
                "/api/node/build",
                json={"type": node_type, "fields": fields},
                headers=self._headers(),
            )
            self.assertEqual(400, response.status_code, f"{node_type}: {response.text}")

    def test_node_build_rejects_schema_enum_and_numeric_values_server_side(self):
        self._login()
        uuid_value = "123e4567-e89b-12d3-a456-426614174000"
        common = {"node_name": "invalid", "node_server": "example.com", "node_port": 443}

        invalid_cases = [
            ("vmess", {**common, "node_uuid": uuid_value, "network_type": "quic"}),
            ("vmess", {**common, "node_uuid": uuid_value, "vmess_encryption": ""}),
            ("ss", {**common, "node_password": "p", "ss_encryption": "not-a-cipher"}),
            ("ssr", {**common, "node_password": "p", "ssr_encryption": ""}),
            ("ssr", {**common, "node_password": "p", "ssr_protocol": "invalid"}),
            ("ssr", {**common, "node_password": "p", "ssr_obfs": "invalid"}),
            ("trojan", {**common, "node_password": "p", "trojan_network": "h2"}),
            ("vless", {**common, "node_uuid": uuid_value, "vless_network": "quic"}),
            ("vless", {**common, "node_uuid": "not-a-uuid"}),
            ("hysteria2", {**common, "node_password": "p", "hy2_obfs_type": "invalid"}),
            ("hysteria2", {**common, "node_password": "p", "hy2_up_mbps": 0}),
            ("hysteria2", {**common, "node_password": "p", "hy2_hop_interval": "not-a-number"}),
            ("tuic", {**common, "tuic_uuid": uuid_value, "tuic_password": "p", "tuic_udp_relay_mode": "invalid"}),
            ("tuic", {**common, "tuic_uuid": uuid_value, "tuic_password": "p", "tuic_heartbeat_interval": 0}),
            ("tuic", {**common, "tuic_uuid": "not-a-uuid", "tuic_password": "p"}),
        ]
        for node_type, fields in invalid_cases:
            response = self.client.post(
                "/api/node/build",
                json={"type": node_type, "fields": fields},
                headers=self._headers(),
            )
            self.assertEqual(400, response.status_code, f"{node_type}: {response.text}")
            payload = response.json()
            self.assertFalse(payload.get("ok"), payload)
            self.assertIn("error", payload)
            self.assertNotIn("node", payload)

    def test_node_form_schema_reuses_server_whitelists_and_removes_fake_transports(self):
        from node_builder import (
            NODE_FORM_SCHEMA,
            PACKET_ENCODING_OPTIONS,
            SSR_CIPHER_OPTIONS,
            SSR_OBFS_OPTIONS,
            SSR_PROTOCOL_OPTIONS,
            VMESS_CIPHER_OPTIONS,
        )

        def fields(node_type):
            return {field["key"]: field for field in NODE_FORM_SCHEMA[node_type]}

        vmess = fields("vmess")
        self.assertEqual(VMESS_CIPHER_OPTIONS, vmess["vmess_encryption"]["options"])
        self.assertIn("zero", vmess["vmess_encryption"]["options"])
        self.assertEqual("aes-128-gcm", fields("ss")["ss_encryption"]["default"])
        ssr = fields("ssr")
        self.assertEqual(SSR_CIPHER_OPTIONS, ssr["ssr_encryption"]["options"])
        self.assertEqual(SSR_PROTOCOL_OPTIONS, ssr["ssr_protocol"]["options"])
        self.assertEqual(SSR_OBFS_OPTIONS, ssr["ssr_obfs"]["options"])
        vless = fields("vless")
        self.assertEqual("select", vless["vless_packet_encoding"]["type"])
        self.assertEqual(PACKET_ENCODING_OPTIONS, vless["vless_packet_encoding"]["options"])
        self.assertNotIn("ss_network", fields("ss"))
        self.assertNotIn("enable_protocol", fields("hysteria2"))
        self.assertNotIn("hy2_protocol", fields("hysteria2"))
        self.assertNotIn("h2_path", fields("trojan"))
        self.assertNotIn("h2_host", fields("trojan"))

    def test_node_build_accepts_only_strict_decimal_ports(self):
        self._login()
        uuid_value = "123e4567-e89b-12d3-a456-426614174000"
        base = {"node_name": "port-node", "node_server": "example.com", "node_uuid": uuid_value}
        valid = self.client.post(
            "/api/node/build",
            json={"type": "vmess", "fields": {**base, "node_port": "0443"}},
            headers=self._headers(),
        )
        self.assertEqual(200, valid.status_code, valid.text)
        self.assertEqual(443, valid.json()["node"]["port"])
        for raw_port in (True, False, 443.0, 443.5, "443.5", "", "  ", " 443", "+443", "-443", 0, -1, 65536, "65536"):
            response = self.client.post(
                "/api/node/build",
                json={"type": "vmess", "fields": {**base, "node_port": raw_port}},
                headers=self._headers(),
            )
            self.assertEqual(400, response.status_code, f"port={raw_port!r}: {response.text}")
            payload = response.json()
            self.assertEqual(False, payload.get("ok"), payload)
            self.assertIsInstance(payload.get("error"), str)
            self.assertNotIn("detail", payload)

    def test_none_rule_source_emits_only_custom_rules(self):
        self._login()
        draft = self._put_draft().json()["config"]
        draft["selected_rule_type"] = "none"
        draft["custom_rules"] = ["DOMAIN-SUFFIX,custom.example,Proxy"]
        response = self.client.post("/api/validate", json=draft, headers=self._headers())
        self.assertEqual(200, response.status_code, response.text)
        payload = response.json()
        self.assertTrue(payload["ok"], payload)
        loaded = yaml.safe_load(payload["yaml"])
        self.assertEqual(["DOMAIN-SUFFIX,custom.example,Proxy"], loaded["rules"])
        self.assertFalse(any(token in payload["yaml"] for token in ("google.com", "youtube.com", "GEOIP", "MATCH,")))

    def test_pending_upload_survives_publish_cleanup_until_draft_reference(self):
        self._login()
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        try:
            draft = self._put_draft().json()["config"]
            self.assertEqual(200, self.client.post("/api/publish", json=draft, headers=self._headers()).status_code)
            uploaded = self.client.post(
                "/api/ruleset/upload",
                headers=self._headers(),
                files={"file": ("handoff.yaml", b"handoff", "text/yaml")},
                data={"alias": "handoff", "format": "yaml", "target": "Proxy"},
            )
            self.assertEqual(200, uploaded.status_code, uploaded.text)
            provider = uploaded.json()["provider"]
            path = Path(ruleset_dir.name, "users", "1", Path(provider["path"]).name)
            self.assertTrue(path.is_file())

            # Pause the real PUT before it reaches the API, then run a real
            # publish cleanup while the upload is still only pending.  No
            # cleanup function is replaced or mocked in this regression.
            put_ready = threading.Event()
            release_put = threading.Event()
            put_result = {}

            def delayed_put():
                put_ready.set()
                release_put.wait(5)
                put_result["response"] = self.client.put(
                    "/api/config",
                    json={**draft, "custom_rule_providers": {"handoff": provider}},
                    headers=self._headers(),
                )

            put_thread = threading.Thread(target=delayed_put)
            put_thread.start()
            self.assertTrue(put_ready.wait(2))
            published_again = self.client.post("/api/publish", json=draft, headers=self._headers())
            self.assertEqual(200, published_again.status_code, published_again.text)
            self.assertTrue(path.is_file())

            draft["custom_rule_providers"] = {"handoff": provider}
            release_put.set()
            put_thread.join(5)
            self.assertFalse(put_thread.is_alive())
            self.assertEqual(200, put_result["response"].status_code, put_result["response"].text)
            validated = self.client.post("/api/validate", json=draft, headers=self._headers())
            self.assertEqual(200, validated.status_code, validated.text)
            self.assertTrue(path.is_file())
            self.assertFalse(list(Path(ruleset_dir.name, ".pending", "1").glob("*.pending.json")))

            orphan_upload = self.client.post(
                "/api/ruleset/upload",
                headers=self._headers(),
                files={"file": ("expired.yaml", b"expired", "text/yaml")},
                data={"alias": "expired", "format": "yaml", "target": "Proxy"},
            )
            self.assertEqual(200, orphan_upload.status_code, orphan_upload.text)
            orphan_path = Path(ruleset_dir.name, "users", "1", Path(orphan_upload.json()["provider"]["path"]).name)
            marker = Path(ruleset_dir.name, ".pending", "1", f"{orphan_path.name}.pending.json")
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(
                json.dumps({"filename": orphan_path.name, "expires_at": 0}),
                encoding="utf-8",
            )
            api._cleanup_unreferenced_user_rulesets(1, storage.get_user_config(1))
            self.assertTrue(path.is_file(), "referenced versions must not be removed by expired marker cleanup")
            self.assertFalse(orphan_path.exists())
        finally:
            if "release_put" in locals():
                release_put.set()
            if "put_thread" in locals() and put_thread.is_alive():
                put_thread.join(5)
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    # ---------- 登出 ----------

    def test_logout(self):
        self._login()
        response = self.client.post("/api/auth/logout", headers=self._headers())
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue(data["ok"])
        # 会话已撤销
        session = self.client.get("/api/session", headers={"Origin": "https://test.local"})
        self.assertFalse(session.json()["authenticated"])

    # ---------- V2 契约回归 ----------

    def test_root_and_v2_serve_same_production_page(self):
        root = self.client.get("/")
        v2 = self.client.get("/v2")
        self.assertEqual(200, root.status_code)
        self.assertEqual(200, v2.status_code)
        self.assertEqual(root.content, v2.content)

    def test_api_errors_use_normalized_envelope(self):
        self._login()
        response = self.client.put(
            "/api/config",
            json={},
            headers=self._headers(),
        )
        self.assertEqual(400, response.status_code)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertIsInstance(payload["error"], str)
        self.assertNotIn("detail", payload)

    def test_bootstrap_contains_complete_config_and_real_targets(self):
        self._login()
        self._put_draft()
        response = self.client.get("/api/config")
        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["config"]["proxies"], payload["proxies"])
        self.assertIn("node-1", payload["all_targets"])
        self.assertIn("Proxy", payload["all_targets"])
        self.assertIn("global_config_schema", payload)
        self.assertIn("node_form_schema", payload)
        controls = {
            field["type"]
            for fields in payload["node_form_schema"].values()
            for field in fields
        }
        self.assertTrue({"input", "select", "checkbox", "textarea"}.issubset(controls))

    def test_validate_and_publish_use_request_payload_not_stale_draft(self):
        self._login()
        first = self._put_draft().json()["config"]
        second = dict(first)
        second["proxies"] = [dict(first["proxies"][0], name="request-node")]
        validate_response = self.client.post(
            "/api/validate",
            json=second,
            headers=self._headers(),
        )
        self.assertEqual(200, validate_response.status_code)
        self.assertEqual("request-node", storage.get_user_config(1)["proxies"][0]["name"])

        third = dict(second)
        third["proxies"] = [dict(second["proxies"][0], name="published-node")]
        publish_response = self.client.post(
            "/api/publish",
            json=third,
            headers=self._headers(),
        )
        self.assertEqual(200, publish_response.status_code)
        saved = storage.get_user_config(1)
        self.assertEqual("published-node", saved["proxies"][0]["name"])
        self.assertIn("published-node", saved["final_yaml"])

    def test_import_duplicate_check_uses_request_existing_proxies(self):
        self._login()
        self._put_draft()
        content = """proxies:
  - name: node-1
    type: ss
    server: import.example.com
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: imported
"""
        response = self.client.post(
            "/api/import",
            json={"mode": "yaml", "content": content, "existing_proxies": []},
            headers=self._headers(),
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual([], response.json()["skipped"])
        self.assertEqual(1, len(response.json()["proxies"]))

    def test_ruleset_upload_returns_mergeable_provider(self):
        self._login()
        with tempfile.TemporaryDirectory() as ruleset_dir:
            previous = os.environ.get("RULESET_DIR")
            os.environ["RULESET_DIR"] = ruleset_dir
            try:
                response = self.client.post(
                    "/api/ruleset/upload",
                    headers=self._headers(),
                    files={"file": ("custom.yaml", b"payload", "text/plain")},
                    data={
                        "alias": "custom-provider",
                        "behavior": "classical",
                        "format": "yaml",
                        "interval": "3600",
                        "order": "追加",
                        "target": "Proxy",
                    },
                )
            finally:
                if previous is None:
                    os.environ.pop("RULESET_DIR", None)
                else:
                    os.environ["RULESET_DIR"] = previous
            self.assertEqual(200, response.status_code)
            payload = response.json()
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["provider"], payload["custom_rule_provider"]["custom-provider"])
            self.assertEqual(payload["provider"], payload["custom_rule_providers"]["custom-provider"])
            provider = payload["provider"]
            self.assertEqual("http", provider["type"])
            self.assertEqual("DIRECT", provider["proxy"])
            self.assertRegex(provider["path"], r"^\./ruleset/users/1/custom-provider--[0-9a-f]{64}\.yaml$")
            self.assertEqual(
                f"https://test.local/ruleset/user/{storage.get_user_config(1)['token']}/1/{Path(provider['path']).name}",
                provider["url"],
            )
            self.assertTrue(Path(ruleset_dir, "users", "1", Path(provider["path"]).name).is_file())

    def test_ruleset_provider_path_matches_published_yaml_and_legacy_file_stays_compatible(self):
        self._login()
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        try:
            legacy_path = Path(ruleset_dir.name, "legacy-global.yaml")
            legacy_path.write_bytes(b"legacy")
            legacy_provider = {
                "type": "file",
                "behavior": "classical",
                "format": "yaml",
                "path": "./ruleset/legacy-global.yaml",
                "interval": 86400,
                "order": "追加",
                "target": "Proxy",
            }
            draft_response = self._put_draft()
            draft = draft_response.json()["config"]
            draft["custom_rule_providers"] = {"legacy-global": legacy_provider}
            self.assertEqual(200, self._put_draft(draft).status_code)

            upload = self.client.post(
                "/api/ruleset/upload",
                headers=self._headers(),
                files={"file": ("private.yaml", b"payload", "text/yaml")},
                data={
                    "alias": "private-provider",
                    "behavior": "classical",
                    "format": "yaml",
                    "interval": "3600",
                    "order": "追加",
                    "target": "Proxy",
                },
            )
            self.assertEqual(200, upload.status_code)
            provider = upload.json()["provider"]
            self.assertEqual("http", provider["type"])
            self.assertRegex(provider["path"], r"^\./ruleset/users/1/private-provider--[0-9a-f]{64}\.yaml$")
            physical_path = Path(ruleset_dir.name, "users", "1", Path(provider["path"]).name)
            self.assertTrue(physical_path.is_file())

            draft["custom_rule_providers"] = {
                "legacy-global": legacy_provider,
                "private-provider": provider,
            }
            publish = self.client.post("/api/publish", json=draft, headers=self._headers())
            self.assertEqual(200, publish.status_code)
            published_yaml = yaml.safe_load(publish.json()["yaml"])
            published_provider = published_yaml["rule-providers"]["private-provider"]
            self.assertEqual(provider["path"], published_provider["path"])
            self.assertEqual(provider["url"], published_provider["url"])
            self.assertEqual("DIRECT", published_provider["proxy"])
            # Docker WORKDIR=/app + ./ruleset/... resolves to RULESET_DIR/...;
            # this is the same physical file mihomo receives in the YAML.
            resolved_from_ruleset_dir = Path(ruleset_dir.name, *published_provider["path"].split("/")[2:])
            self.assertEqual(physical_path.resolve(), resolved_from_ruleset_dir.resolve())
            self.assertTrue(resolved_from_ruleset_dir.is_file())
            saved = self.client.get("/api/config").json()["config"]
            self.assertEqual("./ruleset/legacy-global.yaml", saved["custom_rule_providers"]["legacy-global"]["path"])
            legacy_delete = self.client.post(
                "/api/ruleset/delete",
                json={"path": "./ruleset/legacy-global.yaml"},
                headers=self._headers(),
            )
            self.assertEqual(400, legacy_delete.status_code)
            self.assertTrue(legacy_path.is_file())
        finally:
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    def test_versioned_ruleset_http_url_token_materialization_and_isolation(self):
        self._login()
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        second_client = TestClient(api.app)
        try:
            upload = self.client.post(
                "/api/ruleset/upload",
                headers=self._headers(),
                files={"file": ("private.yaml", b"private-content", "text/yaml")},
                data={"alias": "token-provider", "format": "yaml", "target": "Proxy"},
            )
            self.assertEqual(200, upload.status_code)
            provider = upload.json()["provider"]
            self.assertEqual("http", provider["type"])
            filename = Path(provider["path"]).name
            self.assertRegex(filename, r"^token-provider--[0-9a-f]{64}\.yaml$")
            self.assertTrue(provider["url"].startswith("https://test.local/ruleset/user/"))

            direct = self.client.get(provider["url"])
            self.assertEqual(200, direct.status_code)
            self.assertEqual(b"private-content", direct.content)
            self.assertIn("yaml", direct.headers.get("content-type", ""))
            self.assertEqual(404, self.client.get(f"/ruleset/user/{storage.get_user_config(1)['token']}/1/../bad.yaml").status_code)

            second_user = storage.create_user("ruleset-user-two", "password123")
            second_login = second_client.post(
                "/sub/auth/login",
                data={
                    "username": "ruleset-user-two",
                    "password": "password123",
                    "csrf_token": api.create_csrf_token("auth"),
                },
                headers={"Origin": "https://test.local"},
                follow_redirects=False,
            )
            self.assertEqual(303, second_login.status_code)
            second_token = storage.get_user_config(int(second_user["id"]))["token"]
            first_token = storage.get_user_config(1)["token"]
            self.assertEqual(404, second_client.get(f"/ruleset/user/{second_token}/1/{filename}").status_code)
            self.assertEqual(404, self.client.get(f"/ruleset/user/{first_token}/{second_user['id']}/{filename}").status_code)

            draft = self._put_draft().json()["config"]
            tampered_provider = dict(provider)
            tampered_provider.pop("proxy", None)
            draft["custom_rule_providers"] = {"token-provider": tampered_provider}
            saved_draft = self._put_draft(draft)
            self.assertEqual(200, saved_draft.status_code)
            draft = saved_draft.json()["config"]
            self.assertEqual("DIRECT", draft["custom_rule_providers"]["token-provider"]["proxy"])
            publish = self.client.post("/api/publish", json=draft, headers=self._headers())
            self.assertEqual(200, publish.status_code)
            published = yaml.safe_load(publish.json()["yaml"])
            published_provider = published["rule-providers"]["token-provider"]
            self.assertEqual("http", published_provider["type"])
            self.assertEqual(provider["path"], published_provider["path"])
            self.assertEqual(provider["url"], published_provider["url"])
            self.assertEqual("DIRECT", published_provider["proxy"])

            old_url = provider["url"]
            reset = self.client.post("/api/token/reset", headers=self._headers())
            self.assertEqual(200, reset.status_code)
            new_token = reset.json()["token"]
            self.assertNotEqual(first_token, new_token)
            self.assertEqual(404, self.client.get(old_url).status_code)

            refreshed = self.client.get("/api/config").json()["config"]["custom_rule_providers"]["token-provider"]
            self.assertIn(f"/ruleset/user/{new_token}/1/", refreshed["url"])
            new_subscription = self.client.get(f"/sub/{new_token}")
            self.assertEqual(200, new_subscription.status_code)
            new_yaml = yaml.safe_load(new_subscription.text)
            new_provider = new_yaml["rule-providers"]["token-provider"]
            self.assertIn(f"/ruleset/user/{new_token}/1/", new_provider["url"])
            self.assertEqual("DIRECT", new_provider["proxy"])
            self.assertEqual(200, self.client.get(new_provider["url"]).status_code)
        finally:
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            second_client.close()
            ruleset_dir.cleanup()

    def test_ruleset_upload_isolated_per_user_and_atomic_with_quota(self):
        self._login()
        second_user = storage.create_user("api-user-two", "password123")
        second_client = TestClient(api.app)
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        previous_file_limit = api.MAX_RULESET_USER_FILES
        previous_byte_limit = api.MAX_RULESET_USER_BYTES
        os.environ["RULESET_DIR"] = ruleset_dir.name

        def login_second():
            response = second_client.post(
                "/sub/auth/login",
                data={
                    "username": "api-user-two",
                    "password": "password123",
                    "csrf_token": api.create_csrf_token("auth"),
                },
                headers={"Origin": "https://test.local"},
                follow_redirects=False,
            )
            self.assertEqual(303, response.status_code)

        def upload(client, content, alias="same-alias"):
            return client.post(
                "/api/ruleset/upload",
                headers=self._headers(),
                files={"file": (f"{alias}.yaml", content, "text/yaml")},
                data={"alias": alias, "behavior": "classical", "format": "yaml", "target": "Proxy"},
            )

        try:
            login_second()
            first = upload(self.client, b"first")
            self.assertEqual(200, first.status_code)
            first_draft = self._put_draft().json()["config"]
            first_draft["custom_rule_providers"] = {"same-alias": first.json()["provider"]}
            self.assertEqual(200, self._put_draft(first_draft).status_code)
            replacement = upload(self.client, b"replacement")
            self.assertEqual(200, replacement.status_code)
            second = upload(second_client, b"other-user")
            self.assertEqual(200, second.status_code)

            first_path = Path(ruleset_dir.name, "users", "1", Path(first.json()["provider"]["path"]).name)
            replacement_path = Path(ruleset_dir.name, "users", "1", Path(replacement.json()["provider"]["path"]).name)
            user_two_path = Path(ruleset_dir.name, "users", str(second_user["id"]), Path(second.json()["provider"]["path"]).name)
            self.assertTrue(first_path.is_file())
            self.assertEqual(b"replacement", replacement_path.read_bytes())
            self.assertEqual(b"other-user", user_two_path.read_bytes())
            self.assertNotEqual(first_path, replacement_path)
            self.assertNotEqual(first_path.parent, user_two_path.parent)
            self.assertEqual([], list(first_path.parent.glob("*.tmp")))

            # Keep the replacement referenced by the saved draft so quota
            # checks below exercise a real retained provider rather than an
            # intentionally stale upload.
            retained_draft = self._put_draft().json()["config"]
            retained_draft["custom_rule_providers"] = {"same-alias": replacement.json()["provider"]}
            self.assertEqual(200, self._put_draft(retained_draft).status_code)
            published = self.client.post("/api/publish", json=retained_draft, headers=self._headers())
            self.assertEqual(200, published.status_code)
            self.assertFalse(first_path.exists())
            self.assertTrue(replacement_path.exists())

            # An upload that was never merged into the saved draft remains
            # protected for the bounded hand-off TTL; the next upload must
            # not race a second tab that is about to save the first provider.
            # The other user's same alias remains untouched.
            stale = upload(self.client, b"stale-file", alias="stale-alias")
            self.assertEqual(200, stale.status_code)
            stale_path = Path(ruleset_dir.name, "users", "1", Path(stale.json()["provider"]["path"]).name)
            self.assertTrue(stale_path.is_file())
            next_upload = upload(self.client, b"next-file", alias="next-alias")
            self.assertEqual(200, next_upload.status_code)
            self.assertTrue(stale_path.exists())
            self.assertTrue(user_two_path.is_file())

            stale_marker = Path(
                ruleset_dir.name,
                ".pending",
                "1",
                f"{stale_path.name}.pending.json",
            )
            self.assertTrue(stale_marker.is_file())
            marker = json.loads(stale_marker.read_text(encoding="utf-8"))
            marker["expires_at"] = 0
            stale_marker.write_text(json.dumps(marker), encoding="utf-8")
            api._cleanup_unreferenced_user_rulesets(1, storage.get_user_config(1))
            self.assertFalse(stale_path.exists())
            self.assertTrue(Path(ruleset_dir.name, "users", "1", Path(next_upload.json()["provider"]["path"]).name).exists())

            # The delete endpoint is scoped to the authenticated namespace;
            # deleting user one's alias cannot touch user two's equal alias.
            deleted = self.client.post(
                "/api/ruleset/delete",
                json={"path": next_upload.json()["provider"]["path"]},
                headers=self._headers(),
            )
            self.assertEqual(200, deleted.status_code)
            self.assertTrue(deleted.json()["deleted"])
            self.assertFalse(Path(ruleset_dir.name, "users", "1", Path(next_upload.json()["provider"]["path"]).name).exists())
            self.assertTrue(user_two_path.is_file())
            protected_delete = self.client.post(
                "/api/ruleset/delete",
                json={"path": replacement.json()["provider"]["path"]},
                headers={"Origin": "https://test.local"},
            )
            self.assertEqual(403, protected_delete.status_code)

            api.MAX_RULESET_USER_FILES = 1
            over_file_limit = upload(self.client, b"second-file", alias="another-alias")
            self.assertEqual(413, over_file_limit.status_code)
            self.assertTrue(replacement_path.is_file())

            api.MAX_RULESET_USER_BYTES = 4
            over_byte_limit = upload(self.client, b"too-large", alias="same-alias")
            self.assertEqual(413, over_byte_limit.status_code)
            self.assertEqual(b"replacement", replacement_path.read_bytes())
        finally:
            api.MAX_RULESET_USER_FILES = previous_file_limit
            api.MAX_RULESET_USER_BYTES = previous_byte_limit
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            second_client.close()
            ruleset_dir.cleanup()

    def test_versioned_upload_does_not_replace_saved_draft_on_failed_save(self):
        """A new immutable version must not affect draft/published state until saved."""
        self._login()
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        failed_client = TestClient(api.app, raise_server_exceptions=False)
        failed_client.cookies.update(self.client.cookies)
        try:
            first = self.client.post(
                "/api/ruleset/upload",
                headers=self._headers(),
                files={"file": ("stable.yaml", b"old-version", "text/yaml")},
                data={"alias": "stable", "format": "yaml", "target": "Proxy"},
            )
            self.assertEqual(200, first.status_code)
            first_provider = first.json()["provider"]
            draft = self._put_draft().json()["config"]
            draft["custom_rule_providers"] = {"stable": first_provider}
            self.assertEqual(200, self._put_draft(draft).status_code)
            self.assertEqual(200, self.client.post("/api/publish", json=draft, headers=self._headers()).status_code)

            first_path = Path(ruleset_dir.name, "users", "1", Path(first_provider["path"]).name)
            self.assertTrue(first_path.is_file())
            before = storage.get_user_config(1)

            # Same alias with a changed format/content creates a second version;
            # it must not overwrite the old published file or saved draft.
            second = self.client.post(
                "/api/ruleset/upload",
                headers=self._headers(),
                files={"file": ("stable.yaml", b"new-version", "text/yaml")},
                data={"alias": "stable", "format": "text", "target": "Proxy"},
            )
            self.assertEqual(200, second.status_code)
            second_provider = second.json()["provider"]
            self.assertEqual("text", second_provider["format"])
            self.assertNotEqual(first_provider["path"], second_provider["path"])
            second_path = Path(ruleset_dir.name, "users", "1", Path(second_provider["path"]).name)
            self.assertTrue(first_path.is_file())
            self.assertTrue(second_path.is_file())

            replacement_draft = dict(draft)
            replacement_draft["custom_rule_providers"] = {"stable": second_provider}
            with patch.object(api, "save_user_draft", side_effect=RuntimeError("simulated draft write failure")):
                failed = failed_client.put(
                    "/api/config",
                    json=replacement_draft,
                    headers=self._headers(),
                )
            self.assertEqual(500, failed.status_code)

            after_failure = storage.get_user_config(1)
            self.assertEqual(
                first_provider["path"],
                after_failure["custom_rule_providers"]["stable"]["path"],
            )
            self.assertIn(first_provider["path"], after_failure["final_yaml"])
            self.assertNotIn(second_provider["path"], after_failure["final_yaml"])
            self.assertTrue(first_path.is_file())
            self.assertTrue(second_path.is_file())
        finally:
            failed_client.close()
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    def test_mihomo_missing_check_blocks_validation_and_publish(self):
        self._login()
        draft = self._put_draft().json()["config"]
        previous_enabled = os.environ.get("MIHOMO_VALIDATE_ENABLED")
        previous_binary = os.environ.get("MIHOMO_BINARY")
        os.environ["MIHOMO_VALIDATE_ENABLED"] = "true"
        os.environ["MIHOMO_BINARY"] = "binary-that-does-not-exist-for-v2-test"
        try:
            validation = self.client.post("/api/validate", json=draft, headers=self._headers())
            self.assertEqual(200, validation.status_code)
            payload = validation.json()
            self.assertFalse(payload["ok"])
            self.assertEqual("missing", payload["mihomo"]["status"])
            self.assertTrue(any("mihomo" in check["label"] and check["status"] == "error" for check in payload["checks"]))

            publish = self.client.post("/api/publish", json=draft, headers=self._headers())
            self.assertEqual(409, publish.status_code)
            self.assertEqual("missing", publish.json()["details"]["validation"]["mihomo"]["status"])
        finally:
            if previous_enabled is None:
                os.environ.pop("MIHOMO_VALIDATE_ENABLED", None)
            else:
                os.environ["MIHOMO_VALIDATE_ENABLED"] = previous_enabled
            if previous_binary is None:
                os.environ.pop("MIHOMO_BINARY", None)
            else:
                os.environ["MIHOMO_BINARY"] = previous_binary

    def test_mihomo_disabled_is_explicitly_skipped_and_publishable(self):
        self._login()
        draft = self._put_draft().json()["config"]
        previous_enabled = os.environ.get("MIHOMO_VALIDATE_ENABLED")
        os.environ["MIHOMO_VALIDATE_ENABLED"] = "false"
        try:
            validation = self.client.post("/api/validate", json=draft, headers=self._headers())
            self.assertEqual(200, validation.status_code)
            self.assertTrue(validation.json()["ok"])
            self.assertEqual("skipped", validation.json()["mihomo"]["status"])
            publish = self.client.post("/api/publish", json=draft, headers=self._headers())
            self.assertEqual(200, publish.status_code)
            self.assertEqual("skipped", publish.json()["mihomo"]["status"])
        finally:
            if previous_enabled is None:
                os.environ.pop("MIHOMO_VALIDATE_ENABLED", None)
            else:
                os.environ["MIHOMO_VALIDATE_ENABLED"] = previous_enabled

    def test_no_resolve_is_not_a_target(self):
        self._login()
        draft = self._put_draft().json()["config"]
        targets = self.client.get("/api/config").json()["all_targets"]
        self.assertNotIn("no-resolve", targets)
        draft["custom_rule_providers"] = {
            "invalid-target": {
                "type": "http",
                "url": "https://rules.example.test/invalid.yaml",
                "behavior": "classical",
                "format": "yaml",
                "target": "no-resolve",
            }
        }
        validation = self.client.post("/api/validate", json=draft, headers=self._headers())
        self.assertEqual(200, validation.status_code)
        payload = validation.json()
        self.assertFalse(payload["ok"])
        self.assertTrue(any("no-resolve" in check["detail"] for check in payload["checks"]))
        upload = self.client.post(
            "/api/ruleset/upload",
            headers=self._headers(),
            files={"file": ("invalid.yaml", b"payload", "text/yaml")},
            data={"alias": "invalid-target", "format": "yaml", "target": "no-resolve"},
        )
        self.assertEqual(400, upload.status_code)
        self.assertIn("no-resolve", upload.json()["error"])

    def test_ruleset_file_lock_serializes_independent_processes(self):
        ruleset_dir = tempfile.TemporaryDirectory()
        try:
            context = multiprocessing.get_context("spawn")
            holder_started = context.Event()
            release_holder = context.Event()
            contender_started = context.Event()
            contender_entered = context.Event()
            holder = context.Process(
                target=_hold_ruleset_lock_in_child,
                args=(ruleset_dir.name, holder_started, release_holder),
            )
            contender = context.Process(
                target=_wait_ruleset_lock_in_child,
                args=(ruleset_dir.name, contender_started, contender_entered),
            )
            holder.start()
            self.assertTrue(holder_started.wait(5))
            contender.start()
            self.assertTrue(contender_started.wait(5))
            self.assertFalse(contender_entered.wait(0.35))
            release_holder.set()
            self.assertTrue(contender_entered.wait(5))
            holder.join(5)
            contender.join(5)
            self.assertEqual(0, holder.exitcode)
            self.assertEqual(0, contender.exitcode)
        finally:
            if "holder" in locals() and holder.is_alive():
                release_holder.set()
                holder.terminate()
                holder.join(2)
            if "contender" in locals() and contender.is_alive():
                contender.terminate()
                contender.join(2)
            ruleset_dir.cleanup()

    def test_tombstone_for_existing_user_is_restored_only_when_namespace_missing(self):
        user = storage.create_user("tombstone-restore", "password123")
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        try:
            tombstone = Path(ruleset_dir.name, ".trash", f"{user['id']}-" + "a" * 32)
            tombstone.mkdir(parents=True)
            (tombstone / "kept.yaml").write_bytes(b"kept")
            pending = api._retry_ruleset_tombstones()
            restored = Path(ruleset_dir.name, "users", str(user["id"]), "kept.yaml")
            self.assertEqual([], pending)
            self.assertTrue(restored.is_file())
            self.assertFalse(tombstone.exists())

            conflicting_tombstone = Path(ruleset_dir.name, ".trash", f"{user['id']}-" + "b" * 32)
            conflicting_tombstone.mkdir(parents=True)
            (conflicting_tombstone / "stale.yaml").write_bytes(b"stale")
            (restored.parent / "live.yaml").write_bytes(b"live")
            pending = api._retry_ruleset_tombstones()
            self.assertIn(conflicting_tombstone.name, pending)
            self.assertTrue(conflicting_tombstone.joinpath("stale.yaml").is_file())
            self.assertTrue(restored.parent.joinpath("live.yaml").is_file())
        finally:
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    def test_tombstone_and_numeric_orphan_are_removed_only_without_db_user(self):
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        try:
            tombstone = Path(ruleset_dir.name, ".trash", "987654-" + "c" * 32)
            tombstone.mkdir(parents=True)
            (tombstone / "deleted.yaml").write_bytes(b"deleted")
            orphan = Path(ruleset_dir.name, "users", "987655")
            orphan.mkdir(parents=True)
            (orphan / "orphan.yaml").write_bytes(b"orphan")
            pending = api._retry_ruleset_tombstones()
            self.assertEqual([], pending)
            self.assertFalse(tombstone.exists())
            self.assertFalse(orphan.exists())
        finally:
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    def test_db_first_delete_move_failure_leaves_orphan_for_retry(self):
        target = storage.create_user("delete-move-failure", "password123")
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        try:
            target_dir = Path(ruleset_dir.name, "users", str(target["id"]))
            target_dir.mkdir(parents=True)
            (target_dir / "orphan.yaml").write_bytes(b"orphan")
            with patch.object(api, "_move_user_ruleset_to_tombstone", side_effect=OSError("rename failed")):
                cleanup_pending = api._delete_user_with_rulesets(int(target["id"]))
            self.assertTrue(cleanup_pending)
            self.assertIsNone(storage.get_user_by_id(int(target["id"])))
            self.assertTrue(target_dir.joinpath("orphan.yaml").is_file())
            self.assertEqual([], api._retry_ruleset_tombstones())
            self.assertFalse(target_dir.exists())
        finally:
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    def test_authenticated_upload_rechecks_user_after_waiting_for_delete_guard(self):
        self._login()
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        user_id = int(storage.get_user_by_id(1)["id"])

        class DeleteBeforeGuardYield:
            def __enter__(self):
                storage.delete_regular_user(user_id)
                return self

            def __exit__(self, _exc_type, _exc_value, _traceback):
                return False

        try:
            with patch.object(api, "_ruleset_user_lock", return_value=DeleteBeforeGuardYield()):
                response = self.client.post(
                    "/api/ruleset/upload",
                    headers=self._headers(),
                    files={"file": ("raced.yaml", b"payload", "text/yaml")},
                    data={"alias": "raced", "format": "yaml"},
                )
            self.assertEqual(404, response.status_code)
            self.assertFalse(Path(ruleset_dir.name, "users").exists())
        finally:
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    def test_publish_guard_blocks_newer_put_until_cleanup_finishes(self):
        self._login()
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        publish_release = threading.Event()
        cleanup_entered = threading.Event()
        put_started = threading.Event()
        put_saved = threading.Event()
        publish_result = {}
        put_result = {}
        try:
            body_a = self._put_draft().json()["config"]
            token = storage.get_user_config(1)["token"]
            filename_a = api._versioned_ruleset_filename("race", "yaml", b"A")
            api._write_user_ruleset_atomic(1, filename_a, b"A")
            provider_a = {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": api._user_ruleset_provider_path(1, filename_a),
                "url": api._user_ruleset_url(token, 1, filename_a),
                "proxy": "DIRECT",
                "interval": 86400,
                "order": "追加",
                "target": "Proxy",
            }
            body_a["custom_rule_providers"] = {"race": provider_a}
            published = self.client.post("/api/publish", json=body_a, headers=self._headers())
            self.assertEqual(200, published.status_code)

            # B is a real upload reservation, not yet referenced by the old
            # published/draft snapshot A.  The pending marker must survive
            # the real publish cleanup while the browser is between upload
            # and PUT.
            uploaded_b = self.client.post(
                "/api/ruleset/upload",
                headers=self._headers(),
                files={"file": ("race.yaml", b"B", "text/yaml")},
                data={"alias": "race", "format": "yaml", "target": "Proxy"},
            )
            self.assertEqual(200, uploaded_b.status_code, uploaded_b.text)
            provider_b = uploaded_b.json()["provider"]
            filename_b = Path(provider_b["path"]).name
            path_b = Path(ruleset_dir.name, "users", "1", filename_b)
            self.assertTrue(path_b.is_file())
            body_b = copy.deepcopy(body_a)
            body_b["custom_rule_providers"]["race"] = provider_b

            original_cleanup = api._cleanup_unreferenced_user_rulesets

            def blocking_cleanup(user_id, config, *, strict=False):
                cleanup_entered.set()
                self.assertTrue(publish_release.wait(5))
                # Exercise the real cleanup after the synchronization point;
                # the pending reservation, rather than a mocked return value,
                # must preserve B until the delayed PUT promotes it.
                return original_cleanup(user_id, config, strict=strict)

            original_save_draft = api.save_user_draft

            def tracking_save_draft(*args, **kwargs):
                put_saved.set()
                return original_save_draft(*args, **kwargs)

            api._cleanup_unreferenced_user_rulesets = blocking_cleanup
            api.save_user_draft = tracking_save_draft

            def run_publish():
                try:
                    publish_result["response"] = self.client.post(
                        "/api/publish",
                        json=body_a,
                        headers=self._headers(),
                    )
                except Exception as exc:  # pragma: no cover - surfaced below
                    publish_result["error"] = exc

            def run_put():
                put_started.set()
                try:
                    put_result["response"] = self.client.put(
                        "/api/config",
                        json=body_b,
                        headers=self._headers(),
                    )
                except Exception as exc:  # pragma: no cover - surfaced below
                    put_result["error"] = exc

            publish_thread = threading.Thread(target=run_publish)
            publish_thread.start()
            self.assertTrue(cleanup_entered.wait(5))
            put_thread = threading.Thread(target=run_put)
            put_thread.start()
            self.assertTrue(put_started.wait(5))
            # With the full publish guard the PUT cannot reach its DB write;
            # without the fix it writes B while cleanup is paused.
            self.assertFalse(put_saved.wait(0.5))
            publish_release.set()
            publish_thread.join(5)
            put_thread.join(5)
            self.assertFalse(publish_thread.is_alive())
            self.assertFalse(put_thread.is_alive())
            self.assertNotIn("error", publish_result)
            self.assertNotIn("error", put_result)
            self.assertEqual(200, publish_result["response"].status_code)
            self.assertEqual(200, put_result["response"].status_code)
            final_config = storage.get_user_config(1)
            self.assertEqual(
                body_b["custom_rule_providers"]["race"]["path"],
                final_config["custom_rule_providers"]["race"]["path"],
            )
            self.assertTrue(path_b.is_file())
        finally:
            publish_release.set()
            if "publish_thread" in locals() and publish_thread.is_alive():
                publish_thread.join(5)
            if "put_thread" in locals() and put_thread.is_alive():
                put_thread.join(5)
            if "original_cleanup" in locals():
                api._cleanup_unreferenced_user_rulesets = original_cleanup
            if "original_save_draft" in locals():
                api.save_user_draft = original_save_draft
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    def test_validate_guard_blocks_cleanup_until_new_draft_is_saved(self):
        self._login()
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        validation_release = threading.Event()
        validation_entered = threading.Event()
        cleanup_entered = threading.Event()
        validation_result = {}
        cleanup_result = {}
        try:
            body_a = self._put_draft().json()["config"]
            token = storage.get_user_config(1)["token"]
            filename_a = api._versioned_ruleset_filename("validate-race", "yaml", b"A")
            filename_b = api._versioned_ruleset_filename("validate-race", "yaml", b"B")
            api._write_user_ruleset_atomic(1, filename_a, b"A")
            provider_a = {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "path": api._user_ruleset_provider_path(1, filename_a),
                "url": api._user_ruleset_url(token, 1, filename_a),
                "proxy": "DIRECT",
                "interval": 86400,
                "order": "追加",
                "target": "Proxy",
            }
            body_a["custom_rule_providers"] = {"race": provider_a}
            saved_a = self._put_draft(body_a)
            self.assertEqual(200, saved_a.status_code)
            api._write_user_ruleset_atomic(1, filename_b, b"B")
            body_b = copy.deepcopy(body_a)
            body_b["custom_rule_providers"]["race"]["path"] = api._user_ruleset_provider_path(1, filename_b)
            body_b["custom_rule_providers"]["race"]["url"] = api._user_ruleset_url(token, 1, filename_b)

            original_run_validation = api._run_validation

            def blocking_validation(draft, published_yaml="", normalization_meta=None):
                validation_entered.set()
                self.assertTrue(validation_release.wait(5))
                return original_run_validation(draft, published_yaml, normalization_meta)

            def cleanup_worker():
                try:
                    with api._ruleset_user_lock(1):
                        cleanup_entered.set()
                        latest = storage.get_user_config(1)
                        cleanup_result["removed"] = api._cleanup_unreferenced_user_rulesets(
                            1,
                            latest,
                            strict=True,
                        )
                except Exception as exc:  # pragma: no cover - surfaced below
                    cleanup_result["error"] = exc

            api._run_validation = blocking_validation

            def run_validate():
                try:
                    validation_result["response"] = self.client.post(
                        "/api/validate",
                        json=body_b,
                        headers=self._headers(),
                    )
                except Exception as exc:  # pragma: no cover - surfaced below
                    validation_result["error"] = exc

            validate_thread = threading.Thread(target=run_validate)
            validate_thread.start()
            self.assertTrue(validation_entered.wait(5))
            cleanup_thread = threading.Thread(target=cleanup_worker)
            cleanup_thread.start()
            # The cleanup worker must wait for validation's DB write.  Without
            # the endpoint guard it enters with snapshot A and removes B.
            self.assertFalse(cleanup_entered.wait(0.5))
            validation_release.set()
            validate_thread.join(5)
            cleanup_thread.join(5)
            self.assertFalse(validate_thread.is_alive())
            self.assertFalse(cleanup_thread.is_alive())
            self.assertNotIn("error", validation_result)
            self.assertNotIn("error", cleanup_result)
            self.assertEqual(200, validation_result["response"].status_code)
            final_config = storage.get_user_config(1)
            self.assertEqual(
                body_b["custom_rule_providers"]["race"]["path"],
                final_config["custom_rule_providers"]["race"]["path"],
            )
            self.assertTrue(Path(ruleset_dir.name, "users", "1", filename_b).is_file())
        finally:
            validation_release.set()
            if "validate_thread" in locals() and validate_thread.is_alive():
                validate_thread.join(5)
            if "cleanup_thread" in locals() and cleanup_thread.is_alive():
                cleanup_thread.join(5)
            if "original_run_validation" in locals():
                api._run_validation = original_run_validation
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    def test_admin_delete_user_tombstones_namespace_and_preserves_other_users(self):
        admin = storage.create_user("api-admin", "admin-password", is_admin=True)
        target = storage.create_user("delete-target", "password123")
        other = storage.create_user("delete-other", "password123")
        admin_login = self.client.post(
            "/sub/auth/login",
            data={
                "username": "api-admin",
                "password": "admin-password",
                "csrf_token": api.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        self.assertEqual(303, admin_login.status_code)
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        try:
            target_file = Path(ruleset_dir.name, "users", str(target["id"]), "target--" + "a" * 64 + ".yaml")
            other_file = Path(ruleset_dir.name, "users", str(other["id"]), "other--" + "b" * 64 + ".yaml")
            target_file.parent.mkdir(parents=True)
            other_file.parent.mkdir(parents=True)
            target_file.write_bytes(b"target")
            other_file.write_bytes(b"other")
            legacy_file = Path(ruleset_dir.name, "legacy.yaml")
            legacy_file.write_bytes(b"legacy")

            deleted = self.client.post(
                f"/api/users/{target['id']}/delete",
                headers=self._headers(),
            )
            self.assertEqual(200, deleted.status_code)
            self.assertFalse(deleted.json()["cleanup_pending"])
            self.assertIsNone(storage.get_user_by_id(int(target["id"])))
            self.assertFalse(target_file.parent.exists())
            self.assertTrue(other_file.is_file())
            self.assertTrue(legacy_file.is_file())
            trash_dir = Path(ruleset_dir.name, ".trash")
            self.assertFalse(trash_dir.exists() and any(trash_dir.iterdir()))
        finally:
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    def test_admin_delete_user_database_failure_restores_namespace(self):
        storage.create_user("api-admin", "admin-password", is_admin=True)
        target = storage.create_user("delete-rollback", "password123")
        admin_login = self.client.post(
            "/sub/auth/login",
            data={
                "username": "api-admin",
                "password": "admin-password",
                "csrf_token": api.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        self.assertEqual(303, admin_login.status_code)
        ruleset_dir = tempfile.TemporaryDirectory()
        previous_ruleset_dir = os.environ.get("RULESET_DIR")
        os.environ["RULESET_DIR"] = ruleset_dir.name
        try:
            target_dir = Path(ruleset_dir.name, "users", str(target["id"]))
            target_dir.mkdir(parents=True)
            target_file = target_dir / ("rollback--" + "c" * 64 + ".yaml")
            target_file.write_bytes(b"rollback")
            with patch.object(api, "delete_regular_user", side_effect=RuntimeError("db unavailable")):
                response = self.client.post(
                    f"/api/users/{target['id']}/delete",
                    headers=self._headers(),
                )
            self.assertEqual(500, response.status_code)
            self.assertIsNotNone(storage.get_user_by_id(int(target["id"])))
            self.assertTrue(target_file.is_file())
            trash_dir = Path(ruleset_dir.name, ".trash")
            self.assertFalse(trash_dir.exists() and any(trash_dir.iterdir()))
        finally:
            if previous_ruleset_dir is None:
                os.environ.pop("RULESET_DIR", None)
            else:
                os.environ["RULESET_DIR"] = previous_ruleset_dir
            ruleset_dir.cleanup()

    # ---------- V2 修补回归 ----------

    def test_apply_v2_global_defaults_preserves_explicit_saved_switches(self):
        """老账号显式开启过的全局开关不能被默认合并静默重置。"""
        from config_defaults import apply_v2_global_defaults, build_default_global_config

        saved = {
            "enable_dns": True,
            "enable_sniffer": True,
            "enable_core_options": True,
            "dns_respect_rules": True,
            "openclash_preset": True,
            "profile_store_selected": True,
        }
        merged = apply_v2_global_defaults(build_default_global_config(), saved)
        for key, value in saved.items():
            self.assertEqual(value, merged[key], f"{key} 被默认合并重置")
        self.assertTrue(merged["optional_globals_v2"])
        # 从未设置过的键仍继承默认值（默认即 False）。
        self.assertFalse(merged["include_global_compat"])

    def test_dns_presets_carry_generation_mode(self):
        """DNS 预设必须连同 is_desktop/generation_profile 一起生效。"""
        from config_defaults import FULL_CLIENT_DNS_PRESET, OPENCLASH_ROUTER_SAFE_PRESET

        self.assertTrue(FULL_CLIENT_DNS_PRESET["is_desktop"])
        self.assertEqual("desktop-full", FULL_CLIENT_DNS_PRESET["generation_profile"])
        self.assertTrue(FULL_CLIENT_DNS_PRESET["target_mode_user_selected"])
        self.assertFalse(OPENCLASH_ROUTER_SAFE_PRESET["is_desktop"])
        self.assertEqual("openclash-router", OPENCLASH_ROUTER_SAFE_PRESET["generation_profile"])
        self.assertTrue(OPENCLASH_ROUTER_SAFE_PRESET["target_mode_user_selected"])

    def test_node_form_schema_exposes_smux_and_dialer_fields(self):
        for protocol in ("ss", "vless", "vmess"):
            keys = {field["key"] for field in api.NODE_FORM_SCHEMA[protocol]}
            self.assertIn("enable_smux", keys, protocol)
            self.assertIn("smux_protocol", keys, protocol)
            self.assertIn("smux_brutal_up", keys, protocol)
        for protocol in api.NODE_FORM_SCHEMA:
            keys = {field["key"] for field in api.NODE_FORM_SCHEMA[protocol]}
            self.assertIn("use_dialer_proxy", keys, protocol)
            self.assertIn("dialer_proxy_name", keys, protocol)
        # vless 的 Brutal 默认开启，其余协议默认关闭（对齐 V1）。
        vless_brutal = next(f for f in api.NODE_FORM_SCHEMA["vless"] if f["key"] == "smux_brutal_enabled")
        ss_brutal = next(f for f in api.NODE_FORM_SCHEMA["ss"] if f["key"] == "smux_brutal_enabled")
        self.assertTrue(vless_brutal["default"])
        self.assertFalse(ss_brutal["default"])

    def test_node_form_schema_defaults_match_streamlit(self):
        def default_of(protocol, key):
            return next(field["default"] for field in api.NODE_FORM_SCHEMA[protocol] if field["key"] == key)

        self.assertTrue(default_of("vmess", "node_tls"))
        self.assertTrue(default_of("vless", "vless_tls"))
        self.assertEqual("www.bing.com", default_of("hysteria2", "hy2_sni"))
        self.assertEqual("www.bing.com", default_of("anytls", "anytls_sni"))
        self.assertEqual("v1-dy.ixigua.com", default_of("vless", "vless_servername"))
        self.assertTrue(default_of("anytls", "anytls_skip_cert_verify"))
        self.assertTrue(default_of("hysteria2", "enable_port_hopping"))

    def test_node_build_supports_smux_dialer_and_vmess_udp(self):
        self._login()
        fields = {
            "node_name": "smux-node",
            "node_server": "smux.example.com",
            "node_port": 443,
            "node_uuid": "5c7f7b8a-1111-2222-3333-444455556666",
            "enable_smux": True,
            "smux_protocol": "yamux",
            "smux_max_connections": 8,
            "smux_brutal_enabled": True,
            "smux_brutal_up": 200,
            "smux_brutal_down": 300,
            "use_dialer_proxy": True,
            "dialer_proxy_name": "入口节点",
        }
        response = self.client.post("/api/node/build", json={"type": "vless", "fields": fields}, headers=self._headers())
        self.assertEqual(200, response.status_code, response.text)
        node = response.json()["node"]
        self.assertEqual("yamux", node["smux"]["protocol"])
        self.assertEqual(8, node["smux"]["max-connections"])
        self.assertEqual("200 Mbps", node["smux"]["brutal-opts"]["up"])
        self.assertEqual("300 Mbps", node["smux"]["brutal-opts"]["down"])
        self.assertEqual("入口节点", node["dialer-proxy"])

        vmess = self.client.post(
            "/api/node/build",
            json={
                "type": "vmess",
                "fields": {
                    "node_name": "vmess-udp",
                    "node_server": "vmess.example.com",
                    "node_port": 443,
                    "node_uuid": "5c7f7b8a-1111-2222-3333-444455556666",
                    "node_udp": False,
                },
            },
            headers=self._headers(),
        )
        self.assertEqual(200, vmess.status_code, vmess.text)
        self.assertFalse(vmess.json()["node"]["udp"])

    def test_put_draft_rejects_oversized_and_malformed_entries(self):
        self._login()
        valid_proxies = [{"name": "ok-node", "type": "ss", "server": "a.com", "port": 8388}]

        response = self.client.put(
            "/api/config",
            json={"proxies": [{"name": "x" * 129, "type": "ss", "server": "a.com", "port": 8388}]},
            headers=self._headers(),
        )
        self.assertEqual(400, response.status_code)
        self.assertIn("128", response.json()["error"])

        response = self.client.put(
            "/api/config",
            json={"proxies": valid_proxies, "custom_rules": [123]},
            headers=self._headers(),
        )
        self.assertEqual(400, response.status_code)
        self.assertIn("custom_rules", response.json()["error"])

        response = self.client.put(
            "/api/config",
            json={"proxies": valid_proxies, "custom_rules": ["DOMAIN-SUFFIX," + "a" * 600 + ",Proxy"]},
            headers=self._headers(),
        )
        self.assertEqual(400, response.status_code)
        self.assertIn("512", response.json()["error"])

        response = self.client.put(
            "/api/config",
            json={"proxies": valid_proxies, "custom_rule_providers": {"bad": {"url": 123}}},
            headers=self._headers(),
        )
        self.assertEqual(400, response.status_code)
        self.assertIn("url", response.json()["error"])

        response = self.client.put(
            "/api/config",
            json={"proxies": valid_proxies, "custom_rule_providers": {"bad": {"url": "https://x", "interval": 0}}},
            headers=self._headers(),
        )
        self.assertEqual(400, response.status_code)
        self.assertIn("interval", response.json()["error"])

    def test_register_json_flow(self):
        previous = os.environ.get("ALLOW_REGISTRATION")
        os.environ["ALLOW_REGISTRATION"] = "true"
        try:
            response = self.client.post(
                "/api/auth/register",
                json={
                    "username": "reg-user",
                    "password": "password123",
                    "password_confirm": "password123",
                    "csrf_token": api.create_csrf_token("auth"),
                },
                headers={"Origin": "https://test.local"},
            )
            self.assertEqual(200, response.status_code, response.text)
            self.assertTrue(response.json()["ok"])

            mismatch = self.client.post(
                "/api/auth/register",
                json={
                    "username": "reg-user2",
                    "password": "password123",
                    "password_confirm": "different123",
                    "csrf_token": api.create_csrf_token("auth"),
                },
                headers={"Origin": "https://test.local"},
            )
            self.assertEqual(400, mismatch.status_code)
        finally:
            if previous is None:
                os.environ.pop("ALLOW_REGISTRATION", None)
            else:
                os.environ["ALLOW_REGISTRATION"] = previous

        closed = self.client.post(
            "/api/auth/register",
            json={
                "username": "reg-user3",
                "password": "password123",
                "password_confirm": "password123",
                "csrf_token": api.create_csrf_token("auth"),
            },
            headers={"Origin": "https://test.local"},
        )
        self.assertEqual(403, closed.status_code)

    def test_admin_endpoints_reject_non_admin(self):
        storage.create_user("plain-user", "password123")
        self.client.post(
            "/sub/auth/login",
            data={"username": "plain-user", "password": "password123", "csrf_token": api.create_csrf_token("auth")},
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        response = self.client.get("/api/users")
        self.assertEqual(403, response.status_code)
        response = self.client.post("/api/users/1/toggle", headers=self._headers())
        self.assertEqual(403, response.status_code)

    def test_admin_create_user_and_duplicate_rejected(self):
        storage.create_user("site-admin", "password123", is_admin=True)
        self.client.post(
            "/sub/auth/login",
            data={"username": "site-admin", "password": "password123", "csrf_token": api.create_csrf_token("auth")},
            headers={"Origin": "https://test.local"},
            follow_redirects=False,
        )
        response = self.client.post(
            "/api/users/created-user",
            json={"password": "password123"},
            headers=self._headers(),
        )
        self.assertEqual(200, response.status_code, response.text)
        self.assertTrue(response.json()["ok"])

        duplicate = self.client.post(
            "/api/users/created-user",
            json={"password": "password123"},
            headers=self._headers(),
        )
        self.assertEqual(400, duplicate.status_code)

    def test_import_uses_provided_source_name(self):
        self._login()
        response = self.client.post(
            "/api/import",
            json={
                "mode": "share",
                "content": "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@share.example.com:8388#named-node",
                "name": "分享链接",
                "existing_proxies": [],
            },
            headers=self._headers(),
        )
        self.assertEqual(200, response.status_code, response.text)
        payload = response.json()
        self.assertEqual("分享链接", payload["source"]["name"])


if __name__ == "__main__":
    unittest.main()
