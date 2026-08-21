import os
import tempfile
import unittest

import storage


class AuthSessionTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.previous_db_path = os.environ.get("APP_DB_PATH")
        os.environ["APP_DB_PATH"] = os.path.join(self.tmpdir.name, "app.db")
        storage.init_db()

    def tearDown(self):
        if self.previous_db_path is None:
            os.environ.pop("APP_DB_PATH", None)
        else:
            os.environ["APP_DB_PATH"] = self.previous_db_path
        self.tmpdir.cleanup()

    def test_auth_session_restores_enabled_user(self):
        user = storage.create_user("session-user", "password123")
        token = storage.create_auth_session(int(user["id"]))

        restored = storage.get_user_by_auth_session(token)

        self.assertIsNotNone(restored)
        self.assertEqual("session-user", restored["username"])

    def test_raw_auth_token_is_not_stored(self):
        user = storage.create_user("hashed-user", "password123")
        token = storage.create_auth_session(int(user["id"]))

        with storage._db() as conn:
            row = conn.execute(
                "SELECT token_hash FROM auth_sessions WHERE user_id = ?",
                (int(user["id"]),),
            ).fetchone()

        self.assertNotEqual(token, row["token_hash"])
        self.assertEqual(64, len(row["token_hash"]))

    def test_disabling_user_revokes_existing_sessions(self):
        user = storage.create_user("disabled-user", "password123")
        token = storage.create_auth_session(int(user["id"]))

        storage.set_user_enabled(int(user["id"]), False)

        self.assertIsNone(storage.get_user_by_auth_session(token))

    def test_revoked_session_cannot_restore_user(self):
        user = storage.create_user("logout-user", "password123")
        token = storage.create_auth_session(int(user["id"]))

        storage.revoke_auth_session(token)

        self.assertIsNone(storage.get_user_by_auth_session(token))


if __name__ == "__main__":
    unittest.main()
