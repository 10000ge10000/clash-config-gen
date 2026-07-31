import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from auth import generate_token, hash_password, is_valid_username, verify_password
from config_builder import DEFAULT_RULE_TYPE, build_yaml
from normalizer import normalize_proxies_for_mihomo


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
                import_sources_json TEXT NOT NULL DEFAULT '[]',
                selected_rule_type TEXT NOT NULL DEFAULT 'dustinwin规则',
                final_yaml TEXT NOT NULL DEFAULT '',
                validation_status TEXT NOT NULL DEFAULT 'unknown',
                validation_message TEXT NOT NULL DEFAULT '',
                validated_at TEXT NOT NULL DEFAULT '',
                draft_validation_status TEXT NOT NULL DEFAULT 'unknown',
                draft_validation_message TEXT NOT NULL DEFAULT '',
                draft_validated_at TEXT NOT NULL DEFAULT '',
                published_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL,
                revoked_at TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id
            ON auth_sessions(user_id);

            CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at
            ON auth_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS auth_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                client_ip TEXT NOT NULL DEFAULT '',
                success INTEGER NOT NULL DEFAULT 0,
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_auth_audit_created_at
            ON auth_audit_log(created_at);

            CREATE INDEX IF NOT EXISTS idx_auth_audit_login_lookup
            ON auth_audit_log(event_type, username, client_ip, success, created_at);
            """
        )
        _ensure_subscription_config_columns(conn)
        _migrate_default_rule_type(conn)
        _migrate_mihomo_proxy_fields(conn)


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


def validate_new_user_credentials(username: str, password: str) -> str:
    """在创建账号前完成本地可判定的注册校验。"""
    normalized_username = username.strip()
    if not is_valid_username(normalized_username):
        raise ValueError("用户名必须是 3-32 位字母、数字、下划线、点或短横线")
    if len(password) < 8:
        raise ValueError("密码至少需要 8 位")
    if get_user_by_username(normalized_username) is not None:
        raise ValueError("用户名已存在")
    return normalized_username


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
            INSERT INTO subscription_configs (user_id, token, selected_rule_type, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, generate_token(), DEFAULT_RULE_TYPE, now, now),
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


def record_auth_audit_event(
    event_type: str,
    username: str,
    client_ip: str,
    success: bool,
    detail: str = "",
) -> None:
    """记录不含密码、Cookie 或 Token 的认证审计事件，并限制日志保留期。"""
    now = datetime.now(timezone.utc)
    retention_boundary = now - timedelta(days=90)
    with _connect() as conn:
        conn.execute(
            "DELETE FROM auth_audit_log WHERE created_at < ?",
            (retention_boundary.isoformat(timespec="seconds"),),
        )
        conn.execute(
            """
            INSERT INTO auth_audit_log
                (event_type, username, client_ip, success, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_type[:32],
                username.strip().lower()[:64],
                client_ip[:64],
                int(success),
                detail[:200],
                now.isoformat(timespec="seconds"),
            ),
        )


def recent_login_failure_counts(
    username: str,
    client_ip: str,
    window_seconds: int = 900,
) -> tuple[int, int]:
    """返回时间窗内账号和 IP 的失败次数；账号成功登录后重新计算该账号失败序列。"""
    boundary = datetime.now(timezone.utc) - timedelta(seconds=max(60, window_seconds))
    boundary_text = boundary.isoformat(timespec="seconds")
    normalized_username = username.strip().lower()[:64]
    with _connect() as conn:
        last_success = conn.execute(
            """
            SELECT MAX(created_at) AS created_at
            FROM auth_audit_log
            WHERE event_type = 'login' AND success = 1 AND username = ? AND created_at >= ?
            """,
            (normalized_username, boundary_text),
        ).fetchone()["created_at"]
        username_boundary = max(boundary_text, last_success or boundary_text)
        username_failures = conn.execute(
            """
            SELECT COUNT(*) AS c FROM auth_audit_log
            WHERE event_type = 'login' AND success = 0 AND username = ? AND created_at >= ?
            """,
            (normalized_username, username_boundary),
        ).fetchone()["c"]
        ip_failures = conn.execute(
            """
            SELECT COUNT(*) AS c FROM auth_audit_log
            WHERE event_type = 'login' AND success = 0 AND client_ip = ? AND created_at >= ?
            """,
            (client_ip[:64], boundary_text),
        ).fetchone()["c"]
    return int(username_failures), int(ip_failures)


def create_auth_session(user_id: int, days: int = 30) -> str:
    """创建只在浏览器保存明文、数据库仅保存摘要的持久登录令牌。"""
    user = get_user_by_id(user_id)
    if user is None or not int(user["is_enabled"]):
        raise ValueError("用户不存在或已被禁用")

    token = secrets.token_urlsafe(48)
    token_hash = _hash_auth_token(token)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=max(1, min(days, 90)))
    with _connect() as conn:
        _delete_expired_auth_sessions(conn, now)
        conn.execute(
            """
            INSERT INTO auth_sessions
                (user_id, token_hash, expires_at, created_at, last_used_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                token_hash,
                expires_at.isoformat(timespec="seconds"),
                now.isoformat(timespec="seconds"),
                now.isoformat(timespec="seconds"),
            ),
        )
    return token


def get_user_by_auth_session(token: str) -> sqlite3.Row | None:
    if not token:
        return None

    token_hash = _hash_auth_token(token)
    now = datetime.now(timezone.utc)
    with _connect() as conn:
        _delete_expired_auth_sessions(conn, now)
        row = conn.execute(
            """
            SELECT u.*
            FROM auth_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
              AND s.revoked_at = ''
              AND s.expires_at > ?
              AND u.is_enabled = 1
            """,
            (token_hash, now.isoformat(timespec="seconds")),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE auth_sessions SET last_used_at = ? WHERE token_hash = ?",
                (now.isoformat(timespec="seconds"), token_hash),
            )
        return row


def revoke_auth_session(token: str) -> None:
    if not token:
        return
    with _connect() as conn:
        conn.execute(
            """
            UPDATE auth_sessions
            SET revoked_at = ?
            WHERE token_hash = ? AND revoked_at = ''
            """,
            (utc_now(), _hash_auth_token(token)),
        )


def revoke_user_auth_sessions(user_id: int) -> None:
    with _connect() as conn:
        conn.execute(
            """
            UPDATE auth_sessions
            SET revoked_at = ?
            WHERE user_id = ? AND revoked_at = ''
            """,
            (utc_now(), user_id),
        )


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
        if not enabled:
            conn.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = ?
                WHERE user_id = ? AND revoked_at = ''
                """,
                (utc_now(), user_id),
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
            INSERT INTO subscription_configs (user_id, token, selected_rule_type, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, generate_token(), DEFAULT_RULE_TYPE, now, now),
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
    validation_status: str = "unknown",
    validation_message: str = "",
    import_sources: list[dict[str, Any]] | None = None,
) -> None:
    ensure_user_config(user_id)
    now = utc_now()
    proxies = normalize_proxies_for_mihomo(proxies)
    final_yaml = _normalize_final_yaml_proxies(final_yaml)
    with _connect() as conn:
        conn.execute(
            """
            UPDATE subscription_configs
            SET proxies_json = ?,
                global_config_json = ?,
                custom_rules_json = ?,
                custom_rule_providers_json = ?,
                import_sources_json = ?,
                selected_rule_type = ?,
                final_yaml = ?,
                validation_status = ?,
                validation_message = ?,
                validated_at = ?,
                draft_validation_status = ?,
                draft_validation_message = ?,
                draft_validated_at = ?,
                published_at = ?,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                json.dumps(proxies, ensure_ascii=False),
                json.dumps(global_config, ensure_ascii=False),
                json.dumps(custom_rules, ensure_ascii=False),
                json.dumps(custom_rule_providers, ensure_ascii=False),
                json.dumps(import_sources or [], ensure_ascii=False),
                selected_rule_type,
                final_yaml,
                validation_status,
                validation_message[:2000],
                now if validation_status != "unknown" else "",
                validation_status,
                validation_message[:2000],
                now if validation_status != "unknown" else "",
                now,
                now,
                user_id,
            ),
        )


def save_user_draft(
    user_id: int,
    proxies: list[dict[str, Any]],
    global_config: dict[str, Any],
    custom_rules: list[str],
    custom_rule_providers: dict[str, Any],
    selected_rule_type: str,
    import_sources: list[dict[str, Any]] | None = None,
    validation_status: str = "unknown",
    validation_message: str = "",
) -> None:
    """保存编辑中的配置，不覆盖线上 final_yaml。"""
    ensure_user_config(user_id)
    now = utc_now()
    proxies = normalize_proxies_for_mihomo(proxies)
    with _connect() as conn:
        conn.execute(
            """
            UPDATE subscription_configs
            SET proxies_json = ?,
                global_config_json = ?,
                custom_rules_json = ?,
                custom_rule_providers_json = ?,
                import_sources_json = ?,
                selected_rule_type = ?,
                draft_validation_status = ?,
                draft_validation_message = ?,
                draft_validated_at = ?,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                json.dumps(proxies, ensure_ascii=False),
                json.dumps(global_config, ensure_ascii=False),
                json.dumps(custom_rules, ensure_ascii=False),
                json.dumps(custom_rule_providers, ensure_ascii=False),
                json.dumps(import_sources or [], ensure_ascii=False),
                selected_rule_type,
                validation_status,
                validation_message[:2000],
                now if validation_status != "unknown" else "",
                now,
                user_id,
            ),
        )


def _ensure_subscription_config_columns(conn: sqlite3.Connection) -> None:
    existing_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(subscription_configs)").fetchall()
    }
    for column, definition in {
        "validation_status": "TEXT NOT NULL DEFAULT 'unknown'",
        "validation_message": "TEXT NOT NULL DEFAULT ''",
        "validated_at": "TEXT NOT NULL DEFAULT ''",
        "import_sources_json": "TEXT NOT NULL DEFAULT '[]'",
        "draft_validation_status": "TEXT NOT NULL DEFAULT 'unknown'",
        "draft_validation_message": "TEXT NOT NULL DEFAULT ''",
        "draft_validated_at": "TEXT NOT NULL DEFAULT ''",
        "published_at": "TEXT NOT NULL DEFAULT ''",
    }.items():
        if column not in existing_columns:
            conn.execute(f"ALTER TABLE subscription_configs ADD COLUMN {column} {definition}")


def _migrate_default_rule_type(conn: sqlite3.Connection) -> None:
    """老库里未生成过配置的空白账号默认切到 DustinWin，避免新订阅漏掉 AI/Gemini。"""
    conn.execute(
        """
        UPDATE subscription_configs
        SET selected_rule_type = ?, updated_at = ?
        WHERE selected_rule_type = '自定义规则'
          AND final_yaml = ''
          AND custom_rules_json = '[]'
          AND custom_rule_providers_json = '{}'
        """,
        (DEFAULT_RULE_TYPE, utc_now()),
    )


def _migrate_mihomo_proxy_fields(conn: sqlite3.Connection) -> None:
    """把历史库里的错误 `fingerprint` 字段永久迁移为 mihomo 可加载格式。

    仅在 API 响应时临时清洗不够彻底：OpenClash/Clash Verge 可能缓存旧文件，
    用户重新保存时也可能从旧 `proxies_json` 继续带出脏字段。这里在服务启动
    时直接写回数据库，让保存层和订阅层都保持同一份干净数据。
    """
    rows = conn.execute(
        "SELECT id, proxies_json, final_yaml FROM subscription_configs"
    ).fetchall()
    for row in rows:
        next_proxies_json = row["proxies_json"] or "[]"
        next_final_yaml = row["final_yaml"] or ""
        changed = False

        try:
            proxies = json.loads(next_proxies_json)
        except Exception:
            proxies = []
        if isinstance(proxies, list):
            normalized_proxies = normalize_proxies_for_mihomo(
                [proxy for proxy in proxies if isinstance(proxy, dict)]
            )
            normalized_json = json.dumps(normalized_proxies, ensure_ascii=False)
            if normalized_json != next_proxies_json:
                next_proxies_json = normalized_json
                changed = True

        normalized_yaml = _normalize_final_yaml_proxies(next_final_yaml)
        if normalized_yaml != next_final_yaml:
            next_final_yaml = normalized_yaml
            changed = True

        if changed:
            conn.execute(
                """
                UPDATE subscription_configs
                SET proxies_json = ?, final_yaml = ?, updated_at = ?
                WHERE id = ?
                """,
                (next_proxies_json, next_final_yaml, utc_now(), row["id"]),
            )


def _normalize_final_yaml_proxies(final_yaml: str) -> str:
    if not final_yaml.strip():
        return final_yaml
    try:
        loaded_config = yaml.safe_load(final_yaml)
    except Exception:
        return final_yaml
    if not isinstance(loaded_config, dict):
        return final_yaml
    proxies = loaded_config.get("proxies")
    if not isinstance(proxies, list):
        return final_yaml

    normalized_proxies = normalize_proxies_for_mihomo(
        [proxy for proxy in proxies if isinstance(proxy, dict)]
    )
    if normalized_proxies == proxies:
        return final_yaml
    loaded_config["proxies"] = normalized_proxies
    return build_yaml(loaded_config)


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


def _hash_auth_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def _delete_expired_auth_sessions(
    conn: sqlite3.Connection,
    now: datetime | None = None,
) -> None:
    current = now or datetime.now(timezone.utc)
    conn.execute(
        "DELETE FROM auth_sessions WHERE expires_at <= ?",
        (current.isoformat(timespec="seconds"),),
    )


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
        "import_sources": load_json("import_sources_json", []),
        "selected_rule_type": row["selected_rule_type"],
        "final_yaml": row["final_yaml"] or "",
        "validation_status": row["validation_status"] if "validation_status" in row.keys() else "unknown",
        "validation_message": row["validation_message"] if "validation_message" in row.keys() else "",
        "validated_at": row["validated_at"] if "validated_at" in row.keys() else "",
        "draft_validation_status": row["draft_validation_status"] if "draft_validation_status" in row.keys() else "unknown",
        "draft_validation_message": row["draft_validation_message"] if "draft_validation_message" in row.keys() else "",
        "draft_validated_at": row["draft_validated_at"] if "draft_validated_at" in row.keys() else "",
        "published_at": row["published_at"] if "published_at" in row.keys() else "",
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
