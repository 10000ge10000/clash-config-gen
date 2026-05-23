import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auth import generate_token, hash_password, is_valid_username, verify_password


def get_db_path() -> str:
    """Docker 默认写入 /app/data；Windows 本地开发时回落到项目内 data 目录。"""
    configured = os.getenv("APP_DB_PATH")
    if configured:
        return configured
    if os.name == "nt":
        return str(Path("data") / "app.db")
    return "/app/data/app.db"


def get_public_base_url() -> str:
    """统一生成对外订阅地址，反代场景必须使用公网域名而不是容器内端口。"""
    return os.getenv("PUBLIC_BASE_URL", "https://clash.910501.xyz").rstrip("/")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect() -> sqlite3.Connection:
    db_path = Path(get_db_path())
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """初始化数据库表结构；所有服务启动时都可重复调用。"""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS subscription_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                token TEXT NOT NULL UNIQUE,
                proxies_json TEXT NOT NULL DEFAULT '[]',
                global_config_json TEXT NOT NULL DEFAULT '{}',
                custom_rules_json TEXT NOT NULL DEFAULT '[]',
                custom_rule_providers_json TEXT NOT NULL DEFAULT '{}',
                selected_rule_type TEXT NOT NULL DEFAULT '自定义规则',
                final_yaml TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )


def ensure_admin_from_env() -> None:
    """根据 Docker 环境变量创建管理员，避免把初始账号硬编码进镜像。"""
    username = os.getenv("ADMIN_USERNAME", "").strip()
    password = os.getenv("ADMIN_PASSWORD", "")
    if not username or not password:
        return
    if not is_valid_username(username):
        raise ValueError("ADMIN_USERNAME 只能使用 3-32 位字母、数字、下划线、点或短横线")

    existing = get_user_by_username(username)
    if existing:
        with _connect() as conn:
            conn.execute(
                "UPDATE users SET is_admin = 1, is_enabled = 1, updated_at = ? WHERE id = ?",
                (utc_now(), existing["id"]),
            )
        return

    create_user(username, password, is_admin=True)


def get_user_by_username(username: str) -> sqlite3.Row | None:
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    with _connect() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def create_user(username: str, password: str, is_admin: bool = False) -> sqlite3.Row:
    username = username.strip()
    if not is_valid_username(username):
        raise ValueError("用户名必须是 3-32 位字母、数字、下划线、点或短横线")
    if len(password) < 8:
        raise ValueError("密码至少需要 8 位")

    now = utc_now()
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO users (username, password_hash, is_admin, is_enabled, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?)
            """,
            (username, hash_password(password), int(is_admin), now, now),
        )
        user_id = int(cursor.lastrowid)
        conn.execute(
            """
            INSERT INTO subscription_configs (user_id, token, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, generate_token(), now, now),
        )
    user = get_user_by_id(user_id)
    if user is None:
        raise RuntimeError("用户创建后无法读取")
    return user


def authenticate_user(username: str, password: str) -> sqlite3.Row | None:
    user = get_user_by_username(username)
    if not user or not int(user["is_enabled"]):
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def list_users() -> list[sqlite3.Row]:
    with _connect() as conn:
        return conn.execute(
            """
            SELECT u.id, u.username, u.is_admin, u.is_enabled, u.created_at, u.updated_at,
                   c.token, c.updated_at AS config_updated_at
            FROM users u
            LEFT JOIN subscription_configs c ON c.user_id = u.id
            ORDER BY u.is_admin DESC, u.id ASC
            """
        ).fetchall()


def set_user_enabled(user_id: int, enabled: bool) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET is_enabled = ?, updated_at = ? WHERE id = ?",
            (int(enabled), utc_now(), user_id),
        )


def delete_regular_user(user_id: int) -> None:
    """删除普通用户及其订阅配置；管理员账号不允许通过页面误删。"""
    with _connect() as conn:
        user = conn.execute("SELECT id, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            raise ValueError("用户不存在")
        if int(user["is_admin"]):
            raise ValueError("管理员账号不能在这里删除")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def ensure_user_config(user_id: int) -> sqlite3.Row:
    now = utc_now()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM subscription_configs WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if row:
            return row
        conn.execute(
            """
            INSERT INTO subscription_configs (user_id, token, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, generate_token(), now, now),
        )
    return ensure_user_config(user_id)


def get_user_config(user_id: int) -> dict[str, Any]:
    row = ensure_user_config(user_id)
    return _decode_config_row(row)


def get_config_by_token(token: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT c.*, u.username, u.is_enabled
            FROM subscription_configs c
            JOIN users u ON u.id = c.user_id
            WHERE c.token = ?
            """,
            (token,),
        ).fetchone()
    if not row or not int(row["is_enabled"]):
        return None
    return _decode_config_row(row)


def save_user_config(
    user_id: int,
    proxies: list[dict[str, Any]],
    global_config: dict[str, Any],
    custom_rules: list[str],
    custom_rule_providers: dict[str, Any],
    selected_rule_type: str,
    final_yaml: str,
) -> None:
    ensure_user_config(user_id)
    now = utc_now()
    with _connect() as conn:
        conn.execute(
            """
            UPDATE subscription_configs
            SET proxies_json = ?,
                global_config_json = ?,
                custom_rules_json = ?,
                custom_rule_providers_json = ?,
                selected_rule_type = ?,
                final_yaml = ?,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                json.dumps(proxies, ensure_ascii=False),
                json.dumps(global_config, ensure_ascii=False),
                json.dumps(custom_rules, ensure_ascii=False),
                json.dumps(custom_rule_providers, ensure_ascii=False),
                selected_rule_type,
                final_yaml,
                now,
                user_id,
            ),
        )


def reset_subscription_token(user_id: int) -> str:
    token = generate_token()
    with _connect() as conn:
        conn.execute(
            "UPDATE subscription_configs SET token = ?, updated_at = ? WHERE user_id = ?",
            (token, utc_now(), user_id),
        )
    return token


def health_snapshot() -> dict[str, Any]:
    with _connect() as conn:
        user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        config_count = conn.execute("SELECT COUNT(*) AS c FROM subscription_configs").fetchone()["c"]
    return {
        "status": "ok",
        "database": get_db_path(),
        "users": user_count,
        "configs": config_count,
        "public_base_url": get_public_base_url(),
    }


def _decode_config_row(row: sqlite3.Row) -> dict[str, Any]:
    def load_json(field: str, fallback: Any) -> Any:
        try:
            return json.loads(row[field] or "")
        except Exception:
            return fallback

    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "token": row["token"],
        "proxies": load_json("proxies_json", []),
        "global_config": load_json("global_config_json", {}),
        "custom_rules": load_json("custom_rules_json", []),
        "custom_rule_providers": load_json("custom_rule_providers_json", {}),
        "selected_rule_type": row["selected_rule_type"],
        "final_yaml": row["final_yaml"] or "",
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
