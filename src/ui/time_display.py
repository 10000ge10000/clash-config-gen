"""用户界面时间格式化。

数据库继续保存带时区的 UTC ISO 文本；这里仅在展示边界转换为北京时间，
并兼容历史库中已经保存的非 ISO 文本。
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo


BEIJING = ZoneInfo("Asia/Shanghai")


def format_beijing_time(value, fallback: str = "尚未发布") -> str:
    """把有效 ISO 时间格式化为 ``YYYY-MM-DD HH:mm:ss 北京时间``。

    空值使用 fallback；无法解析的旧文本原样返回，避免历史数据被误改写。
    无时区的 ISO 文本按 UTC 处理，因为现有存储层的时间语义是 UTC。
    """
    if value is None or value == "":
        return fallback
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(BEIJING).strftime("%Y-%m-%d %H:%M:%S 北京时间")
