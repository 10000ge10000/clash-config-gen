import os
import tempfile
import unittest

from config_builder import build_config, build_yaml
from diagnostics import build_subscription_diagnostics
from storage import create_user, init_db, save_user_config


class ApiDiagnosticsTest(unittest.TestCase):
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
