"""用镜像内的 mihomo 校验所有已发布订阅（只读数据库），供 auto-update-mihomo.sh 在切换新内核前调用。

在新镜像里以 `python /validate_published.py` 运行，PYTHONPATH=/app；数据目录以只读方式挂载到 /app/data。
任何一份订阅未通过就以非零退出码结束，脚本据此放弃升级。输出不含 token、节点等敏感信息。
"""
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

# geodata 目录复制到临时目录，避免 mihomo 往只读数据卷写文件。
home = Path(tempfile.mkdtemp(prefix="mihomo-home-"))
source_home = Path("/app/data/mihomo-home")
if source_home.is_dir():
    for item in source_home.iterdir():
        if item.is_file():
            shutil.copy(item, home / item.name)
os.environ["MIHOMO_HOME"] = str(home)

from mihomo_validator import validate_with_mihomo  # noqa: E402

# 数据卷只读、库为 WAL 模式时 SQLite 无法直接打开（需要写 -shm），先把库和 WAL 复制到临时目录再读。
db_dir = Path(tempfile.mkdtemp(prefix="app-db-"))
for suffix in ("", "-wal"):
    source = Path(f"/app/data/app.db{suffix}")
    if source.is_file():
        shutil.copy(source, db_dir / f"app.db{suffix}")
conn = sqlite3.connect(str(db_dir / "app.db"))
rows = conn.execute(
    "SELECT u.username, c.final_yaml FROM subscription_configs c JOIN users u ON u.id = c.user_id "
    "WHERE c.final_yaml <> '' ORDER BY u.id"
).fetchall()
failed = 0
for username, final_yaml in rows:
    result = validate_with_mihomo(final_yaml, timeout=120)
    ok = result.status == "passed"
    failed += not ok
    last_line = (str(result.message or "").strip().splitlines() or [""])[-1][:200]
    print(f"{'通过' if ok else '失败'} {username}: {result.status} {'' if ok else last_line}")
print(f"共 {len(rows)} 份已发布订阅，失败 {failed} 份")
sys.exit(1 if failed or not rows else 0)
