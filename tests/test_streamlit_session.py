import unittest

from ui.auth_view import refresh_auth_user


def _user(**kw):
    base = {"id": 7, "username": "alice", "is_admin": 0, "is_enabled": 1}
    base.update(kw)
    return base


class RefreshAuthUserTests(unittest.TestCase):
    def test_valid_session_refreshes_latest_privileges(self):
        state = {"auth_user": {"id": 7, "username": "alice", "is_admin": True}}
        result = refresh_auth_user(state, "tok", lambda t: _user(is_admin=0))
        self.assertFalse(result["is_admin"])
        self.assertFalse(state["auth_user"]["is_admin"])

    def test_revoked_session_clears_state(self):
        state = {"auth_user": {"id": 7}, "session_loaded_user_id": 7}
        self.assertIsNone(refresh_auth_user(state, "tok", lambda t: None))
        self.assertIsNone(state["auth_user"])
        self.assertNotIn("session_loaded_user_id", state)

    def test_missing_token_clears_state_without_lookup(self):
        state = {"auth_user": {"id": 7}}
        called = []
        refresh_auth_user(state, "", lambda t: called.append(t))
        self.assertIsNone(state["auth_user"])
        self.assertEqual([], called)

    def test_disabled_user_clears_state(self):
        state = {"auth_user": {"id": 7}}
        self.assertIsNone(refresh_auth_user(state, "tok", lambda t: _user(is_enabled=0)))
        self.assertIsNone(state["auth_user"])


if __name__ == "__main__":
    unittest.main()
