import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("update_mihomo", ROOT / ".github/scripts/update_mihomo.py")
update_mihomo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(update_mihomo)


class UpdateMihomoTest(unittest.TestCase):
    def test_should_upgrade_only_newer_stable_same_major(self):
        self.assertEqual(True, update_mihomo.should_upgrade("v1.19.33", "v1.19.34")[0])
        self.assertEqual(True, update_mihomo.should_upgrade("v1.19.33", "v1.20.0")[0])
        self.assertEqual(False, update_mihomo.should_upgrade("v1.19.33", "v1.19.33")[0])
        self.assertEqual(False, update_mihomo.should_upgrade("v1.19.34", "v1.19.33")[0])
        self.assertEqual(False, update_mihomo.should_upgrade("v1.19.33", "Prerelease-Alpha")[0])
        self.assertEqual(False, update_mihomo.should_upgrade("v1.19.33", "v2.0.0")[0])

    def test_rewrite_dockerfile_touches_only_mihomo_args(self):
        original = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        args = update_mihomo.read_args(original)
        self.assertEqual({"MIHOMO_VERSION", "MIHOMO_SHA256_AMD64", "MIHOMO_SHA256_ARM64"}, set(args))
        rewritten = update_mihomo.rewrite_dockerfile(original, "v1.99.0", {"amd64": "a" * 64, "arm64": "b" * 64})
        self.assertEqual(
            {"MIHOMO_VERSION": "v1.99.0", "MIHOMO_SHA256_AMD64": "a" * 64, "MIHOMO_SHA256_ARM64": "b" * 64},
            update_mihomo.read_args(rewritten),
        )
        changed = [
            (old, new) for old, new in zip(original.splitlines(), rewritten.splitlines()) if old != new
        ]
        self.assertEqual(3, len(changed))
        self.assertTrue(all(new.startswith("ARG MIHOMO_") for _old, new in changed))

    def test_rewrite_dockerfile_rejects_missing_arg(self):
        with self.assertRaises(SystemExit):
            update_mihomo.rewrite_dockerfile("FROM scratch\n", "v1.99.0", {"amd64": "a", "arm64": "b"})


if __name__ == "__main__":
    unittest.main()
