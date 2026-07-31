import logging
import os
import threading
import time
from pathlib import Path

import requests

from config_builder import (
    DUSTINWIN_PROVIDERS_MAP,
    DUSTINWIN_RULESET_BASE_URL,
    DUSTINWIN_RULESET_INTERVAL,
    get_ruleset_update_interval,
)

LOGGER = logging.getLogger(__name__)
RULESET_CACHE_DIR = Path(os.getenv("RULESET_CACHE_DIR", "/app/ruleset/dustinwin"))
_STARTED = False


def ruleset_cache_enabled() -> bool:
    raw = os.getenv("RULESET_CACHE_ENABLED", "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def get_ruleset_cache_path(file_name: str) -> Path:
    safe_name = Path(file_name).name
    return RULESET_CACHE_DIR / safe_name


def update_dustinwin_rulesets(timeout: int = 30) -> dict[str, int]:
    """下载内置规则集到本地缓存；失败不覆盖已有可用文件。"""
    RULESET_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    stats = {"updated": 0, "failed": 0}
    source_urls = {
        str(config["file"]): str(config.get("url") or f"{DUSTINWIN_RULESET_BASE_URL}/{config['file']}")
        for config in DUSTINWIN_PROVIDERS_MAP.values()
    }

    for file_name, url in sorted(source_urls.items()):
        target_path = get_ruleset_cache_path(file_name)
        temp_path = target_path.with_suffix(target_path.suffix + ".tmp")
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            if not response.content:
                raise RuntimeError("下载内容为空")
            temp_path.write_bytes(response.content)
            os.replace(temp_path, target_path)
            stats["updated"] += 1
        except Exception as exc:
            stats["failed"] += 1
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            LOGGER.warning("更新 DustinWin 规则集失败: %s (%s)", file_name, exc)
    return stats


def _background_loop() -> None:
    interval = max(get_ruleset_update_interval(), 3600)
    while True:
        stats = update_dustinwin_rulesets()
        LOGGER.info(
            "DustinWin 规则集更新完成: updated=%s failed=%s next=%ss",
            stats["updated"],
            stats["failed"],
            interval,
        )
        time.sleep(interval)


def start_ruleset_update_worker() -> None:
    global _STARTED
    if _STARTED or not ruleset_cache_enabled():
        return
    _STARTED = True
    initial_delay = int(os.getenv("RULESET_INITIAL_UPDATE_DELAY", "5") or "5")

    def delayed_start() -> None:
        time.sleep(max(initial_delay, 0))
        _background_loop()

    thread = threading.Thread(target=delayed_start, name="ruleset-updater", daemon=True)
    thread.start()


def expected_ruleset_interval() -> int:
    return max(get_ruleset_update_interval(), DUSTINWIN_RULESET_INTERVAL)
