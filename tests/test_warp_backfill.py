import os
import tempfile
import unittest
from unittest.mock import patch

import storage
from backfill_warp_masque import _preflight


class WarpBackfillStorageTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {
                "APP_DB_PATH": os.path.join(self.tmpdir.name, "app.db"),
                "WARP_PRESET_NAME": "预制masque",
            },
        )
        self.env.start()
        storage.init_db()

    def tearDown(self):
        self.env.stop()
        self.tmpdir.cleanup()

    def test_regular_user_listing_excludes_admin(self):
        storage.create_user("admin-user", "password123", is_admin=True)
        regular = storage.create_user("regular-user", "password123")

        users = storage.list_regular_user_configs()

        self.assertEqual([int(regular["id"])], [user["user_id"] for user in users])

    def test_existing_preset_name_stops_before_provisioning(self):
        user = storage.create_user("existing-user", "password123")
        storage.save_user_config(
            int(user["id"]),
            proxies=[{"name": "预制masque", "type": "masque"}],
            global_config={},
            custom_rules=[],
            custom_rule_providers={},
            selected_rule_type="dustinwin规则",
            final_yaml="",
        )

        with self.assertRaisesRegex(ValueError, "已有同名节点"):
            _preflight()

    def test_atomic_batch_rolls_back_when_any_snapshot_is_stale(self):
        first = storage.create_user("first-user", "password123")
        second = storage.create_user("second-user", "password123")
        first_config = storage.get_user_config(int(first["id"]))
        second_config = storage.get_user_config(int(second["id"]))
        updates = []
        for config in (first_config, second_config):
            updates.append(
                {
                    "user_id": config["user_id"],
                    "expected_updated_at": config["updated_at"],
                    "proxies": [],
                    "global_config": {},
                    "custom_rules": [],
                    "custom_rule_providers": {},
                    "import_sources": [],
                    "selected_rule_type": "dustinwin规则",
                    "final_yaml": "",
                }
            )
        updates[1]["expected_updated_at"] = "stale"

        with self.assertRaisesRegex(ValueError, "已回滚全部写入"):
            storage.publish_user_configs_atomically(updates)

        self.assertEqual([], storage.get_user_config(int(first["id"]))["proxies"])
        self.assertEqual(first_config["updated_at"], storage.get_user_config(int(first["id"]))["updated_at"])
        self.assertEqual(second_config["updated_at"], storage.get_user_config(int(second["id"]))["updated_at"])


if __name__ == "__main__":
    unittest.main()
