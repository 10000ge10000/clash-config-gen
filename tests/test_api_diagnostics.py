import os
import tempfile
import unittest
import base64
from pathlib import Path

from config_builder import SUBSCRIPTION_ANNOUNCE, build_config, build_subscription_headers, build_yaml
from diagnostics import build_subscription_diagnostics
from storage import create_user, init_db, save_user_config


class ApiDiagnosticsTest(unittest.TestCase):
    def test_dustinwin_ruleset_endpoint_returns_cached_file(self):
        try:
            from fastapi import HTTPException  # noqa: F401
        except ModuleNotFoundError:
            self.skipTest("fastapi 未安装，跳过 API 路由测试")
        import ruleset_updater
        from api import get_dustinwin_ruleset

        with tempfile.TemporaryDirectory() as tmpdir:
            previous_cache_dir = ruleset_updater.RULESET_CACHE_DIR
            ruleset_updater.RULESET_CACHE_DIR = Path(tmpdir)
            try:
                Path(tmpdir, "ai.mrs").write_bytes(b"mrs-data")
                response = get_dustinwin_ruleset("ai.mrs")

                self.assertEqual(b"mrs-data", response.body)
                self.assertEqual("application/octet-stream", response.media_type)
                self.assertEqual("DustinWin/ruleset_geodata", response.headers["x-clash-ruleset-source"])
            finally:
                ruleset_updater.RULESET_CACHE_DIR = previous_cache_dir

    def test_dustinwin_ruleset_endpoint_rejects_missing_cache(self):
        try:
            from fastapi import HTTPException
        except ModuleNotFoundError:
            self.skipTest("fastapi 未安装，跳过 API 路由测试")
        import ruleset_updater
        from api import get_dustinwin_ruleset

        with tempfile.TemporaryDirectory() as tmpdir:
            previous_cache_dir = ruleset_updater.RULESET_CACHE_DIR
            ruleset_updater.RULESET_CACHE_DIR = Path(tmpdir)
            try:
                with self.assertRaises(HTTPException) as context:
                    get_dustinwin_ruleset("ai.mrs")

                self.assertEqual(503, context.exception.status_code)
            finally:
                ruleset_updater.RULESET_CACHE_DIR = previous_cache_dir

    def test_subscription_response_exposes_clash_metadata_headers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            previous_db_path = os.environ.get("APP_DB_PATH")
            os.environ["APP_DB_PATH"] = os.path.join(tmpdir, "app.db")
            try:
                init_db()
                user = create_user("meta-user", "password123")
                config = build_config(
                    [
                        {
                            "name": "sample",
                            "type": "ss",
                            "server": "127.0.0.1",
                            "port": 8388,
                            "cipher": "aes-128-gcm",
                            "password": "password",
                        }
                    ],
                    {"generation_profile": "minimal"},
                )
                save_user_config(
                    int(user["id"]),
                    config["proxies"],
                    {"generation_profile": "minimal"},
                    [],
                    {},
                    "自定义规则",
                    build_yaml(config),
                    validation_status="passed",
                    validation_message="ok",
                )

                saved_config = diagnostics_config_for_user(int(user["id"]))
                header_items = {
                    key.lower(): value
                    for key, value in build_subscription_headers(
                        len(saved_config["proxies"]),
                        2,
                    ).items()
                }

                self.assertNotIn("subscription-userinfo", header_items)
                self.assertEqual("24", header_items["profile-update-interval"])
                self.assertEqual("Clash-Config-Gen", header_items["profile-title"])
                self.assertIn("clash-config-gen", header_items["profile-web-page-url"])
                self.assertEqual("https://clash.910501.xyz", header_items["support-url"])
                self.assertEqual("https://clash.910501.xyz", header_items["x-clash-config-project-url"])
                self.assertTrue(header_items["announce"].startswith("base64:"))
                decoded_announce = base64.b64decode(
                    header_items["announce"].removeprefix("base64:")
                ).decode("utf-8")
                self.assertEqual(SUBSCRIPTION_ANNOUNCE, decoded_announce)
            finally:
                if previous_db_path is None:
                    os.environ.pop("APP_DB_PATH", None)
                else:
                    os.environ["APP_DB_PATH"] = previous_db_path

    def test_diagnostics_returns_non_sensitive_subscription_stats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            previous_db_path = os.environ.get("APP_DB_PATH")
            os.environ["APP_DB_PATH"] = os.path.join(tmpdir, "app.db")
            try:
                init_db()
                user = create_user("diag-user", "password123")
                config = build_config(
                    [
                        {
                            "name": "sample",
                            "type": "ss",
                            "server": "127.0.0.1",
                            "port": 8388,
                            "cipher": "aes-128-gcm",
                            "password": "password",
                        }
                    ],
                    {"generation_profile": "minimal"},
                )
                save_user_config(
                    int(user["id"]),
                    config["proxies"],
                    {"generation_profile": "minimal"},
                    [],
                    {},
                    "自定义规则",
                    build_yaml(config),
                    validation_status="passed",
                    validation_message="ok",
                )

                saved_config = diagnostics_config_for_user(int(user["id"]))
                diagnostics = build_subscription_diagnostics(saved_config, config)

                self.assertEqual(1, diagnostics["proxy_count"])
                self.assertEqual(2, diagnostics["proxy_group_count"])
                self.assertEqual(0, diagnostics["fingerprint_count"])
                self.assertTrue(diagnostics["has_proxy_group"])
                self.assertTrue(diagnostics["has_match_rule"])
                self.assertNotIn("password", diagnostics)
            finally:
                if previous_db_path is None:
                    os.environ.pop("APP_DB_PATH", None)
                else:
                    os.environ["APP_DB_PATH"] = previous_db_path


def diagnostics_config_for_user(user_id: int) -> dict:
    from storage import get_user_config

    return get_user_config(user_id)


if __name__ == "__main__":
    unittest.main()
