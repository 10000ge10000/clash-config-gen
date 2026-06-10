import json
import os
import sqlite3
import tempfile
import unittest

import yaml

import storage
from config_builder import build_yaml


class StorageMigrationTest(unittest.TestCase):
    def test_init_db_migrates_blank_legacy_rule_type_to_dustinwin(self):
        """未生成过配置的旧空白账号应迁移到 DustinWin 默认规则源。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "app.db")
            previous_db_path = os.environ.get("APP_DB_PATH")
            os.environ["APP_DB_PATH"] = db_path
            try:
                storage.init_db()
                with sqlite3.connect(db_path) as conn:
                    conn.execute(
                        """
                        INSERT INTO users (id, username, password_hash, is_admin, is_enabled, created_at, updated_at)
                        VALUES (1, 'legacy', 'hash', 0, 1, 'now', 'now')
                        """
                    )
                    conn.execute(
                        """
                        INSERT INTO subscription_configs
                            (user_id, token, selected_rule_type, final_yaml, custom_rules_json, custom_rule_providers_json, created_at, updated_at)
                        VALUES (1, 'token', '自定义规则', '', '[]', '{}', 'now', 'now')
                        """
                    )

                storage.init_db()

                self.assertEqual("dustinwin规则", storage.get_user_config(1)["selected_rule_type"])
            finally:
                if previous_db_path is None:
                    os.environ.pop("APP_DB_PATH", None)
                else:
                    os.environ["APP_DB_PATH"] = previous_db_path

    def test_init_db_persistently_migrates_legacy_fingerprint_fields(self):
        """服务启动时必须把历史数据库里的错误 fingerprint 永久写回干净值。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "app.db")
            previous_db_path = os.environ.get("APP_DB_PATH")
            os.environ["APP_DB_PATH"] = db_path
            try:
                storage.init_db()
                dirty_proxies = [
                    {
                        "name": "hy2",
                        "type": "hysteria2",
                        "server": "example.com",
                        "port": 443,
                        "password": "secret",
                        "fingerprint": "chrome",
                    }
                ]
                dirty_yaml = build_yaml(
                    {
                        "proxies": dirty_proxies,
                        "proxy-groups": [
                            {"name": "Proxy", "type": "select", "proxies": ["hy2"]},
                        ],
                        "rules": ["MATCH,Proxy"],
                    }
                )

                with sqlite3.connect(db_path) as conn:
                    conn.execute(
                        """
                        INSERT INTO users (id, username, password_hash, is_admin, is_enabled, created_at, updated_at)
                        VALUES (1, 'legacy', 'hash', 0, 1, 'now', 'now')
                        """
                    )
                    conn.execute(
                        """
                        INSERT INTO subscription_configs (user_id, token, proxies_json, final_yaml, created_at, updated_at)
                        VALUES (1, 'token', ?, ?, 'now', 'now')
                        """,
                        (json.dumps(dirty_proxies, ensure_ascii=False), dirty_yaml),
                    )

                storage.init_db()

                with sqlite3.connect(db_path) as conn:
                    row = conn.execute(
                        "SELECT proxies_json, final_yaml FROM subscription_configs WHERE user_id = 1"
                    ).fetchone()

                migrated_proxies = json.loads(row[0])
                migrated_yaml = yaml.safe_load(row[1])
                self.assertNotIn("fingerprint", migrated_proxies[0])
                self.assertEqual("chrome", migrated_proxies[0]["client-fingerprint"])
                self.assertNotIn("fingerprint", migrated_yaml["proxies"][0])
                self.assertEqual("chrome", migrated_yaml["proxies"][0]["client-fingerprint"])
            finally:
                if previous_db_path is None:
                    os.environ.pop("APP_DB_PATH", None)
                else:
                    os.environ["APP_DB_PATH"] = previous_db_path


if __name__ == "__main__":
    unittest.main()
