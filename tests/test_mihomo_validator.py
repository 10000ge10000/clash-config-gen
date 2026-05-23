import os
import unittest

from mihomo_validator import validate_with_mihomo


class MihomoValidatorTest(unittest.TestCase):
    def test_validation_can_be_disabled_for_local_development(self):
        previous = os.environ.get("MIHOMO_VALIDATE_ENABLED")
        os.environ["MIHOMO_VALIDATE_ENABLED"] = "false"
        try:
            result = validate_with_mihomo("not: yaml: but skipped")
        finally:
            if previous is None:
                os.environ.pop("MIHOMO_VALIDATE_ENABLED", None)
            else:
                os.environ["MIHOMO_VALIDATE_ENABLED"] = previous

        self.assertFalse(result.enabled)
        self.assertTrue(result.ok)
        self.assertEqual("skipped", result.status)


if __name__ == "__main__":
    unittest.main()
