import hashlib
import hmac
import os
import re
import secrets


PASSWORD_ALGORITHM = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 260_000
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def is_valid_username(username: str) -> bool:
    """限制用户名字符集，避免把 UI 输入直接变成难以维护的数据库标识。"""
    return bool(USERNAME_PATTERN.fullmatch((username or "").strip()))


def hash_password(password: str) -> str:
    """使用标准库 PBKDF2 保存密码，不引入额外依赖，方便 Docker 镜像稳定构建。"""
    if not password:
        raise ValueError("密码不能为空")

    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
    ).hex()
    return f"{PASSWORD_ALGORITHM}${PASSWORD_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    """恒定时间比较密码哈希，避免登录接口泄露可被利用的时间差。"""
    try:
        algorithm, iterations, salt, expected = stored_hash.split("$", 3)
        if algorithm != PASSWORD_ALGORITHM:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations),
        ).hex()
        return hmac.compare_digest(digest, expected)
    except Exception:
        return False


def generate_token() -> str:
    """生成订阅 Token。Token 足够长，订阅接口无需登录态也能安全鉴权。"""
    return secrets.token_urlsafe(32)


def get_bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
