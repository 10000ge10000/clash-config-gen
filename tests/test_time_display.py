import unittest

from ui.time_display import format_beijing_time


class BeijingTimeDisplayTest(unittest.TestCase):
    def test_iso_timestamp_is_converted_for_display(self):
        self.assertEqual(
            "2026-08-20 08:00:00 北京时间",
            format_beijing_time("2026-08-20T00:00:00+00:00"),
        )

    def test_empty_value_uses_fallback(self):
        self.assertEqual("未发布", format_beijing_time(None, fallback="未发布"))

    def test_legacy_text_is_preserved(self):
        self.assertEqual("历史文本", format_beijing_time("历史文本"))


if __name__ == "__main__":
    unittest.main()
