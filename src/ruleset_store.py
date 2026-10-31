"""用户私有规则集的生命周期：跨进程用户锁、版本化文件、待引用标记、
回收站（tombstone）与孤儿目录清理，以及依赖同一把用户锁的账号启停/删除。

FastAPI（api.py）与 Streamlit（web_app.py）共用本模块；这里不构建 FastAPI app，
Streamlit 导入本模块不会触发 API 路由装配。
"""

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

if os.name == "nt":
    import msvcrt
else:
    import fcntl

import yaml
from fastapi import HTTPException

from storage import (
    delete_regular_user,
    get_db_instance_id,
    get_public_base_url,
    get_user_by_id,
    get_user_config,
    list_users,
    set_user_enabled,
)


LOGGER = logging.getLogger(__name__)


def _has_any_user() -> bool:
    try:
        return bool(list_users())
    except Exception:
        LOGGER.exception("读取用户表失败，按空用户表处理")
        return False


MAX_RULESET_UPLOAD_BYTES = 4 * 1024 * 1024
MAX_RULESET_USER_BYTES = 32 * 1024 * 1024
MAX_RULESET_USER_FILES = 100
RULESET_EXTENSIONS = {"list", "yaml", "yml", "txt", "text", "mrs"}
RULESET_FORMATS = {"text", "yaml", "mrs"}
RULESET_BEHAVIORS = {"classical", "domain", "ipcidr"}
RULESET_ORDERS = {"优先 (覆盖)", "默认 (追加)", "追加", "prepend", "append"}
RULESET_FORMAT_EXTENSIONS = {"text": "txt", "yaml": "yaml", "mrs": "mrs"}

# 规则集上传需要在“配额检查 → 临时文件写入 → os.replace”整个窗口内
# 对同一用户串行化。threading.Lock 只解决同进程并发，文件锁同时覆盖
# FastAPI 与 Streamlit 两个进程；锁文件只存放在 RULESET_DIR/.locks/ 下。
_RULESET_USER_LOCKS: dict[int, threading.Lock] = {}
_RULESET_USER_LOCKS_GUARD = threading.Lock()


def _ruleset_lock_dir() -> Path:
    """Return the private, application-owned directory for process locks."""
    base_dir = Path(_ruleset_dir()).resolve()
    lexical_lock_dir = base_dir / ".locks"
    if lexical_lock_dir.is_symlink():
        raise ValueError("规则集锁目录不能是符号链接")
    lock_dir = lexical_lock_dir.resolve()
    if base_dir not in lock_dir.parents:
        raise ValueError("规则集锁目录路径越界")
    lock_dir.mkdir(parents=True, exist_ok=True)
    if lock_dir.is_symlink() or not lock_dir.is_dir():
        raise ValueError("规则集锁目录不是安全目录")
    return lock_dir


def _acquire_ruleset_file_lock(handle) -> None:
    """Acquire one byte in a lock file using only the standard library."""
    handle.seek(0)
    if handle.tell() == 0 and handle.seek(0, os.SEEK_END) == 0:
        handle.write(b"0")
        handle.flush()
        handle.seek(0)
    else:
        handle.seek(0)

    if os.name == "nt":
        # msvcrt locking is per-process and needs a real byte in the file.
        # Non-blocking attempts avoid msvcrt's implementation-dependent retry
        # interval while still making the context manager block reliably.
        while True:
            try:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                time.sleep(0.05)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _release_ruleset_file_lock(handle) -> None:
    try:
        handle.seek(0)
        if os.name == "nt":
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        # Closing the descriptor below still releases an advisory lock.  Do
        # not mask the original exception from the protected operation.
        pass


@contextmanager
def _ruleset_user_lock(user_id: int):
    """Serialize one user's ruleset lifecycle across threads and processes."""
    numeric_id = int(user_id)
    if numeric_id < 1:
        raise ValueError("用户 ID 无效")
    with _RULESET_USER_LOCKS_GUARD:
        thread_lock = _RULESET_USER_LOCKS.setdefault(numeric_id, threading.Lock())
    with thread_lock:
        lock_dir = _ruleset_lock_dir()
        lock_path = lock_dir / f"{numeric_id}.lock"
        if lock_path.is_symlink():
            raise ValueError("规则集用户锁不能是符号链接")
        try:
            if lock_path.resolve().parent != lock_dir:
                raise ValueError("规则集用户锁路径越界")
        except OSError as exc:
            raise ValueError("规则集用户锁路径无效") from exc
        handle = lock_path.open("a+b")
        try:
            _acquire_ruleset_file_lock(handle)
            yield
        finally:
            _release_ruleset_file_lock(handle)
            handle.close()


def _reload_ruleset_user(user_id: int) -> dict:
    """Reload a user after acquiring the ruleset lifecycle guard."""
    current = get_user_by_id(int(user_id))
    if current is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not bool(current["is_enabled"]):
        raise HTTPException(status_code=409, detail="用户已被禁用")
    return dict(current)


def _reload_admin_actor_locked(actor_id: int) -> dict:
    """Re-read the administrator inside a target-user lifecycle guard."""
    actor = get_user_by_id(int(actor_id))
    if actor is None or not bool(actor["is_enabled"]):
        raise HTTPException(status_code=401, detail="管理员会话已失效")
    if not bool(actor["is_admin"]):
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return dict(actor)


def _materialize_private_provider_urls(user_id: int, token: str, providers: object) -> bool:
    """Rewrite only current-user private provider URLs to the active token."""
    if not isinstance(providers, dict):
        return False
    changed = False
    for provider in providers.values():
        if not isinstance(provider, dict):
            continue
        filename = _private_ruleset_filename(user_id, str(provider.get("path") or ""))
        if not filename:
            continue
        next_url = _user_ruleset_url(token, user_id, filename)
        if provider.get("url") != next_url:
            provider["url"] = next_url
            changed = True
        # Private providers are fetched by the subscription client itself;
        # never let a stale/edited draft route them through a dummy proxy.
        if provider.get("proxy") != "DIRECT":
            provider["proxy"] = "DIRECT"
            changed = True
    return changed


def _materialize_private_urls_in_draft(user: dict, draft: dict, token: str | None = None) -> bool:
    active_token = token
    if active_token is None:
        active_token = str(get_user_config(int(user["id"])).get("token") or "")
    return _materialize_private_provider_urls(
        int(user["id"]),
        str(active_token or ""),
        draft.get("custom_rule_providers") if isinstance(draft, dict) else {},
    )


def _materialize_private_urls_in_loaded_config(config: dict, loaded_config: dict) -> bool:
    return _materialize_private_provider_urls(
        int(config.get("user_id") or 0),
        str(config.get("token") or ""),
        loaded_config.get("rule-providers") if isinstance(loaded_config, dict) else {},
    )


def _ruleset_dir() -> str:
    default = "/app/ruleset" if os.name != "nt" else "ruleset"
    return os.getenv("RULESET_DIR", default)


def _ruleset_users_dir() -> Path:
    """Return the numeric per-user namespace root after symlink checks."""
    base_dir = Path(_ruleset_dir()).resolve()
    lexical_users_dir = base_dir / "users"
    if lexical_users_dir.is_symlink():
        raise ValueError("规则集用户根目录不能是符号链接")
    users_dir = lexical_users_dir.resolve()
    if base_dir not in users_dir.parents:
        raise ValueError("规则集用户根目录路径越界")
    return users_dir


def _ruleset_user_dir(user_id: int) -> Path:
    """Return the private physical namespace for one user's uploads.

    Physical upload files are isolated below ``users/<numeric-id>/`` so equal
    aliases never collide.  Existing drafts that reference the old global
    ``./ruleset/<alias>.<ext>`` path remain untouched by normalization and are
    intentionally outside this namespace.
    """
    users_dir = _ruleset_users_dir()
    lexical_user_dir = users_dir / str(int(user_id))
    if lexical_user_dir.is_symlink():
        raise ValueError("规则集用户目录不能是符号链接")
    user_dir = lexical_user_dir.resolve()
    if users_dir not in user_dir.parents:
        raise ValueError("规则集用户目录路径越界")
    return user_dir


_VERSIONED_RULESET_FILENAME_PATTERN = re.compile(
    r"^(?P<alias>[A-Za-z0-9][A-Za-z0-9._-]{0,63})--(?P<digest>[0-9a-f]{64})\.(?P<extension>yaml|txt|mrs)$"
)
_RULESET_TOMBSTONE_PATTERN = re.compile(r"^(?P<user_id>[0-9]+)-(?P<nonce>[0-9a-f]{32})$")
_RULESET_PENDING_MARKER_SUFFIX = ".pending.json"
_DEFAULT_RULESET_PENDING_TTL_SECONDS = 15 * 60


def _ruleset_pending_ttl_seconds() -> int:
    """Return the bounded lifetime of an upload not yet referenced by config."""
    raw = os.getenv("RULESET_PENDING_TTL_SECONDS")
    try:
        value = int(raw) if raw is not None else _DEFAULT_RULESET_PENDING_TTL_SECONDS
    except (TypeError, ValueError):
        value = _DEFAULT_RULESET_PENDING_TTL_SECONDS
    return max(1, min(value, 7 * 24 * 60 * 60))


def _ruleset_pending_root() -> Path:
    base_dir = Path(_ruleset_dir()).resolve()
    lexical_pending = base_dir / ".pending"
    if lexical_pending.is_symlink():
        raise ValueError("规则集待引用目录不能是符号链接")
    pending_root = lexical_pending.resolve()
    if base_dir not in pending_root.parents:
        raise ValueError("规则集待引用目录路径越界")
    return pending_root


def _ruleset_pending_user_dir(user_id: int) -> Path:
    pending_root = _ruleset_pending_root()
    lexical_user_dir = pending_root / str(int(user_id))
    if lexical_user_dir.is_symlink():
        raise ValueError("规则集待引用用户目录不能是符号链接")
    user_dir = lexical_user_dir.resolve()
    if pending_root not in user_dir.parents:
        raise ValueError("规则集待引用用户目录路径越界")
    return user_dir


def _pending_marker_path(user_id: int, filename: str) -> Path | None:
    if not _parse_versioned_ruleset_filename(filename):
        return None
    pending_dir = _ruleset_pending_user_dir(user_id)
    lexical = pending_dir / f"{filename}{_RULESET_PENDING_MARKER_SUFFIX}"
    try:
        resolved = lexical.resolve()
    except OSError:
        return None
    if lexical.parent != pending_dir.resolve() or resolved.parent != pending_dir.resolve() or lexical.is_symlink():
        return None
    return lexical


def _pending_ruleset_filenames(user_id: int) -> set[str]:
    """Read active upload reservations and discard expired/malformed markers."""
    pending_dir = _ruleset_pending_user_dir(user_id)
    if not pending_dir.exists():
        return set()
    if pending_dir.is_symlink() or not pending_dir.is_dir():
        raise OSError("规则集待引用用户目录不是安全目录")
    now = time.time()
    active: set[str] = set()
    for marker in pending_dir.iterdir():
        if marker.is_symlink() or not marker.is_file() or not marker.name.endswith(_RULESET_PENDING_MARKER_SUFFIX):
            continue
        filename = marker.name[: -len(_RULESET_PENDING_MARKER_SUFFIX)]
        remove = False
        try:
            with marker.open("r", encoding="utf-8") as handle:
                metadata = json.load(handle)
            expires_at = float(metadata.get("expires_at", 0))
            if metadata.get("filename") != filename or expires_at <= now:
                remove = True
            elif _parse_versioned_ruleset_filename(filename):
                active.add(filename)
            else:
                remove = True
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            remove = True
        if remove:
            try:
                marker.unlink()
            except OSError:
                pass
    return active


def _reserve_pending_ruleset(user_id: int, filename: str) -> None:
    """Atomically reserve an immutable upload until draft/publish references it."""
    marker = _pending_marker_path(user_id, filename)
    if marker is None:
        raise ValueError("规则集待引用文件名无效")
    pending_dir = marker.parent
    pending_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "filename": filename,
        "created_at": time.time(),
        "expires_at": time.time() + _ruleset_pending_ttl_seconds(),
    }
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            prefix=f".{filename}.",
            suffix=".tmp",
            dir=pending_dir,
            encoding="utf-8",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(metadata, temporary, ensure_ascii=False, separators=(",", ":"))
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, marker)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _release_pending_marker(user_id: int, filename: str) -> None:
    marker = _pending_marker_path(user_id, filename)
    if marker is None:
        return
    try:
        marker.unlink()
    except FileNotFoundError:
        pass


def _remove_pending_user_namespace(user_id: int) -> None:
    """Remove only one user's reservation namespace after DB deletion."""
    pending_dir = _ruleset_pending_user_dir(user_id)
    if not pending_dir.exists():
        return
    if pending_dir.is_symlink() or not pending_dir.is_dir():
        raise OSError("规则集待引用用户目录不是安全目录")
    shutil.rmtree(pending_dir)


def _promote_referenced_pending_rulesets(user_id: int, config: dict | None) -> None:
    """Release reservations that are now durable draft/published references."""
    user_dir = _ruleset_user_dir(user_id)
    referenced = _referenced_user_rulesets_for_config(user_id, config, user_dir)
    for filename in _pending_ruleset_filenames(user_id):
        target = _safe_user_ruleset_target(user_dir, filename)
        if target is None or not target.exists() or target in referenced:
            _release_pending_marker(user_id, filename)


def _user_ruleset_provider_path(user_id: int, filename: str) -> str:
    """Return the mihomo cache path for one versioned private file."""
    return f"./ruleset/users/{int(user_id)}/{filename}"


def _versioned_ruleset_filename(alias: str, extension: str, content: bytes) -> str:
    digest = hashlib.sha256(content).hexdigest()
    return f"{alias}--{digest}.{extension}"


def _parse_versioned_ruleset_filename(filename: str) -> tuple[str, str] | None:
    match = _VERSIONED_RULESET_FILENAME_PATTERN.fullmatch(str(filename or ""))
    if not match:
        return None
    return match.group("alias"), match.group("extension")


def _private_ruleset_filename(user_id: int, provider_path: str) -> str | None:
    normalized = str(provider_path or "").replace("\\", "/")
    prefix = f"./ruleset/users/{int(user_id)}/"
    if not normalized.startswith(prefix):
        return None
    filename = normalized[len(prefix):]
    if "/" in filename or not _parse_versioned_ruleset_filename(filename):
        return None
    return filename


def _safe_user_ruleset_target(user_dir: Path, filename: str) -> Path | None:
    """Resolve one version filename without following an escaping symlink."""
    lexical = user_dir / filename
    try:
        resolved = lexical.resolve()
    except OSError:
        return None
    base = user_dir.resolve()
    if lexical.parent != base or resolved.parent != base or lexical.is_symlink():
        return None
    return resolved


def _user_ruleset_url(token: str, user_id: int, filename: str) -> str:
    return (
        f"{get_public_base_url()}/ruleset/user/"
        f"{quote(str(token), safe='')}/{int(user_id)}/{quote(filename, safe='')}"
    )


def _ruleset_storage_extension(format_value: str) -> str:
    """Map the public provider format to the canonical on-disk extension."""
    normalized = str(format_value or "").strip().lower()
    if normalized in RULESET_FORMAT_EXTENSIONS:
        return RULESET_FORMAT_EXTENSIONS[normalized]
    # Accept extension-shaped values for an idempotent delete call from older
    # clients, but always resolve to the same canonical extension used by
    # upload.  No path component is accepted here.
    extension_map = {
        "yaml": "yaml",
        "yml": "yaml",
        "txt": "txt",
        "text": "txt",
        "list": "txt",
        "mrs": "mrs",
    }
    if normalized in extension_map:
        return extension_map[normalized]
    raise ValueError("format 只能是 text、yaml 或 mrs")


RULESET_DB_INSTANCE_MARKER = ".db-instance-id"


def _ruleset_db_instance_matches() -> bool:
    """判断当前数据库是否就是写出这批规则集的数据库；只用于决定能否做孤儿目录清理。

    - 标记文件缺失：调用方已确认 DB 有用户，此时“认领”（写入标记）但本次仍跳过孤儿清理；
    - 标记与 DB 实例标识一致：返回 True；
    - 不一致或读取失败：记录 error 并返回 False，宁可留下孤儿也不误删其他库的用户规则集。
    """
    try:
        db_instance_id = get_db_instance_id()
    except Exception:
        LOGGER.exception("读取数据库实例标识失败，跳过规则集孤儿目录清理")
        return False
    base_dir = Path(_ruleset_dir())
    marker = base_dir / RULESET_DB_INSTANCE_MARKER
    if marker.is_symlink():
        LOGGER.error("规则集实例标记 %s 是符号链接，跳过孤儿目录清理", marker)
        return False
    if not marker.exists():
        try:
            base_dir.mkdir(parents=True, exist_ok=True)
            tmp_path = base_dir / f"{RULESET_DB_INSTANCE_MARKER}.{uuid.uuid4().hex}.tmp"
            tmp_path.write_text(db_instance_id + "\n", encoding="utf-8")
            os.replace(tmp_path, marker)
        except OSError:
            LOGGER.exception("写入规则集实例标记失败，跳过孤儿目录清理")
            return False
        LOGGER.warning(
            "规则集目录缺少数据库实例标记，已由当前数据库认领；本次跳过孤儿目录清理，下次启动起正常回收"
        )
        return False
    try:
        recorded = marker.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        LOGGER.exception("读取规则集实例标记失败，跳过孤儿目录清理")
        return False
    if recorded != db_instance_id:
        LOGGER.error(
            "规则集目录属于另一个数据库实例（标记 %s，当前库 %s），疑似数据卷挂载错误；已跳过孤儿目录清理",
            recorded[:64],
            db_instance_id,
        )
        return False
    return True


def _ruleset_trash_dir() -> Path:
    base_dir = Path(_ruleset_dir()).resolve()
    lexical_trash_dir = base_dir / ".trash"
    if lexical_trash_dir.is_symlink():
        raise ValueError("规则集回收目录不能是符号链接")
    trash_dir = lexical_trash_dir.resolve()
    if base_dir not in trash_dir.parents:
        raise ValueError("规则集回收目录路径越界")
    return trash_dir


def _retry_ruleset_tombstones() -> list[str]:
    """Recover/delete tombstones and purge orphaned numeric user namespaces.

    Every decision is made after taking the user's cross-process lock and
    re-reading the database.  A database row wins over filesystem cleanup:
    valid users are never deleted, and a tombstone is restored only when its
    original namespace is absent.
    """
    pending: list[str] = []
    # 用户表为空通常意味着新库或数据卷没挂上；此时下面所有“DB 无此用户”
    # 的判断都不可信，继续执行会把全部用户规则集移入回收站并删除。
    if not _has_any_user():
        LOGGER.warning("用户表为空，跳过规则集回收站与孤儿目录清理，避免误删全部用户规则集")
        return pending
    try:
        trash_dir = _ruleset_trash_dir()
    except ValueError:
        return []
    if trash_dir.is_dir() and not trash_dir.is_symlink():
        try:
            tombstones = list(trash_dir.iterdir())
        except OSError:
            tombstones = []
        for item in tombstones:
            match = _RULESET_TOMBSTONE_PATTERN.fullmatch(item.name)
            if not match:
                continue
            user_id = int(match.group("user_id"))
            try:
                with _ruleset_user_lock(user_id):
                    # Re-read the DB inside the guard.  Another process may
                    # have recreated or deleted the account since scanning.
                    db_user = get_user_by_id(user_id)
                    user_dir = _ruleset_user_dir(user_id)
                    if item.is_symlink() or not item.is_dir():
                        pending.append(item.name)
                        continue
                    if db_user is not None:
                        users_dir = _ruleset_users_dir()
                        if user_dir.exists() or user_dir.is_symlink():
                            # Never overwrite valid user data with a stale
                            # tombstone.  Leave it for an explicit retry.
                            pending.append(item.name)
                            continue
                        users_dir.mkdir(parents=True, exist_ok=True)
                        os.replace(item, user_dir)
                    else:
                        shutil.rmtree(item)
            except Exception:
                pending.append(item.name)

    # A process can die after the DB commit and before rename().  Reconcile
    # numeric user directories only when the database confirms the user is
    # gone; all other directories and all symlinks are left untouched.
    try:
        users_dir = _ruleset_users_dir()
    except ValueError:
        return pending
    if users_dir.is_dir() and not users_dir.is_symlink():
        # 数据库与规则集目录不是同一实例（数据卷挂错）时，“DB 无此用户”不可信，
        # 跳过孤儿目录与待引用标记的清理；上面的 tombstone 已按明确删除照常处理。
        if not _ruleset_db_instance_matches():
            return pending
        try:
            orphan_candidates = list(users_dir.iterdir())
        except OSError:
            orphan_candidates = []
        for item in orphan_candidates:
            if not re.fullmatch(r"[0-9]+", item.name):
                continue
            if item.is_symlink() or not item.is_dir():
                continue
            user_id = int(item.name)
            try:
                with _ruleset_user_lock(user_id):
                    if get_user_by_id(user_id) is not None:
                        continue
                    moved = _move_user_ruleset_to_tombstone(user_id)
                    if moved is None:
                        continue
                    _orphan_user_dir, tombstone = moved
                    try:
                        shutil.rmtree(tombstone)
                    except OSError:
                        pending.append(tombstone.name)
            except Exception:
                pending.append(item.name)

    # Reservation markers live outside users/<id>.  Once the DB row is gone,
    # they are safe to remove in the same user guard; never touch a namespace
    # whose account still exists.
    try:
        pending_root = _ruleset_pending_root()
    except ValueError:
        pending_root = None
    if pending_root is not None and pending_root.is_dir() and not pending_root.is_symlink():
        try:
            pending_candidates = list(pending_root.iterdir())
        except OSError:
            pending_candidates = []
        for item in pending_candidates:
            if not re.fullmatch(r"[0-9]+", item.name) or item.is_symlink() or not item.is_dir():
                continue
            user_id = int(item.name)
            try:
                with _ruleset_user_lock(user_id):
                    if get_user_by_id(user_id) is None:
                        _remove_pending_user_namespace(user_id)
            except Exception:
                pending.append(item.name)
    return pending


def _move_user_ruleset_to_tombstone(user_id: int) -> tuple[Path, Path] | None:
    user_dir = _ruleset_user_dir(user_id)
    if not user_dir.exists():
        return None
    if user_dir.is_symlink() or not user_dir.is_dir():
        raise OSError("规则集用户目录不是安全目录")
    trash_dir = _ruleset_trash_dir()
    trash_dir.mkdir(parents=True, exist_ok=True)
    tombstone = (trash_dir / f"{int(user_id)}-{uuid.uuid4().hex}").resolve()
    if trash_dir not in tombstone.parents:
        raise ValueError("规则集回收文件路径越界")
    os.replace(user_dir, tombstone)
    return user_dir, tombstone


def _delete_user_with_rulesets(user_id: int, actor_id: int | None = None) -> bool:
    """Delete DB rows first, then detach and remove the user's file namespace.

    Once the DB transaction succeeds, the subscription token is invalid even
    if a process crashes before the filesystem rename.  Such an orphan is
    reclaimed by ``_retry_ruleset_tombstones`` on startup or admin actions.

    ``actor_id`` is rechecked after acquiring the target lock.  It is optional
    only for internal recovery tests/callers that already have no actor; all
    admin API and Streamlit entry points pass it explicitly.
    """
    with _ruleset_user_lock(user_id):
        if actor_id is not None:
            _reload_admin_actor_locked(actor_id)
        target = get_user_by_id(int(user_id))
        if target is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        if bool(target["is_admin"]):
            raise HTTPException(status_code=403, detail="管理员账号不能在这里删除")
        # DB-first is intentional: if this raises, no filesystem operation has
        # happened and the caller can safely retry without restoration logic.
        delete_regular_user(user_id)
        try:
            moved = _move_user_ruleset_to_tombstone(user_id)
        except Exception:
            return True
        try:
            _remove_pending_user_namespace(user_id)
        except Exception:
            # The account is already gone; leave the inaccessible reservation
            # namespace for the next tombstone/orphan retry.
            return True
        if moved is None:
            return False
        _user_dir, tombstone = moved
        try:
            shutil.rmtree(tombstone)
            return False
        except Exception:
            return True


def _ruleset_user_usage(user_dir: Path) -> tuple[int, int]:
    if not user_dir.is_dir():
        return 0, 0
    total_bytes = 0
    file_count = 0
    for item in user_dir.iterdir():
        if not item.is_file():
            continue
        try:
            total_bytes += item.stat().st_size
        except OSError:
            continue
        file_count += 1
    return total_bytes, file_count


def _referenced_user_rulesets_from_providers(
    user_id: int,
    providers: object,
    user_dir: Path,
) -> set[Path]:
    """Resolve only versioned providers in one current-user namespace."""
    referenced: set[Path] = set()
    if not isinstance(providers, dict):
        return referenced
    for provider in providers.values():
        if not isinstance(provider, dict):
            continue
        filename = _private_ruleset_filename(user_id, str(provider.get("path") or ""))
        if filename:
            target = _safe_user_ruleset_target(user_dir, filename)
            if target is not None:
                referenced.add(target)
    return referenced


def _referenced_user_rulesets(user_id: int, draft: dict | None, user_dir: Path) -> set[Path]:
    providers = (draft or {}).get("custom_rule_providers") if isinstance(draft, dict) else {}
    return _referenced_user_rulesets_from_providers(user_id, providers, user_dir)


def _all_user_ruleset_files(user_dir: Path) -> set[Path]:
    """Return a conservative keep-set when a published document is unreadable."""
    if not user_dir.is_dir():
        return set()
    return {
        item.resolve()
        for item in user_dir.iterdir()
        if item.is_file() and not item.is_symlink()
    }


def _referenced_user_rulesets_from_yaml(user_id: int, final_yaml: str, user_dir: Path) -> set[Path]:
    if not str(final_yaml or "").strip():
        return set()
    try:
        loaded = yaml.safe_load(final_yaml)
    except Exception:
        # Never delete a published version merely because an older YAML is
        # temporarily unreadable; the next successful publish can reclaim it.
        return _all_user_ruleset_files(user_dir)
    if not isinstance(loaded, dict):
        return _all_user_ruleset_files(user_dir)
    return _referenced_user_rulesets_from_providers(user_id, loaded.get("rule-providers"), user_dir)


def _referenced_user_rulesets_for_config(user_id: int, config: dict | None, user_dir: Path) -> set[Path]:
    config = config if isinstance(config, dict) else {}
    return (
        _referenced_user_rulesets(user_id, config, user_dir)
        | _referenced_user_rulesets_from_yaml(user_id, str(config.get("final_yaml") or ""), user_dir)
    )


def _cleanup_unreferenced_user_rulesets(
    user_id: int,
    config: dict | None,
    *,
    strict: bool = False,
) -> list[Path]:
    """Remove stale files from one user's namespace only.

    This is intentionally called while the per-user upload lock is held.  It
    cleans failed/abandoned versions before the next quota check, but retains
    every version referenced by either the saved draft or published YAML.
    """
    user_dir = _ruleset_user_dir(user_id)
    referenced = _referenced_user_rulesets_for_config(user_id, config, user_dir)
    # An upload response is intentionally a short-lived reservation window:
    # the browser still has to PUT the provider into the draft.  Keep those
    # immutable files across a concurrent publish cleanup, but release the
    # marker as soon as the reference becomes durable.  Expired markers are
    # removed by _pending_ruleset_filenames and become eligible below.
    for filename in _pending_ruleset_filenames(user_id):
        target = _safe_user_ruleset_target(user_dir, filename)
        if target is None or not target.exists():
            _release_pending_marker(user_id, filename)
            continue
        if target in referenced:
            _release_pending_marker(user_id, filename)
            continue
        referenced.add(target)
    if not user_dir.is_dir():
        return []
    removed: list[Path] = []
    failures: list[OSError] = []
    for item in user_dir.iterdir():
        if not item.is_file() or item.resolve() in referenced:
            continue
        try:
            item.unlink()
        except OSError as exc:
            failures.append(exc)
            continue
        removed.append(item)
    if strict and failures:
        raise OSError("部分旧规则集版本清理失败") from failures[0]
    return removed


def _write_user_ruleset_atomic(user_id: int, filename: str, content: bytes) -> Path:
    """Write one immutable version atomically and enforce per-user quotas."""
    parsed = _parse_versioned_ruleset_filename(filename)
    if not parsed:
        raise ValueError("规则集版本文件名无效")
    alias, _extension = parsed
    user_dir = _ruleset_user_dir(user_id)
    user_dir.mkdir(parents=True, exist_ok=True)
    target = _safe_user_ruleset_target(user_dir, filename)
    if target is None:
        raise ValueError("规则集文件路径越界")
    if target.exists():
        if target.is_file() and target.read_bytes() == content:
            return target
        raise ValueError("规则集版本文件冲突")
    total_bytes, file_count = _ruleset_user_usage(user_dir)
    new_total = total_bytes + len(content)
    new_count = file_count + 1
    if new_total > MAX_RULESET_USER_BYTES:
        raise ValueError(f"该用户规则集总大小超过 {MAX_RULESET_USER_BYTES} bytes 配额")
    if new_count > MAX_RULESET_USER_FILES:
        raise ValueError(f"该用户规则集文件数超过 {MAX_RULESET_USER_FILES} 个配额")

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{alias}.",
            suffix=".tmp",
            dir=user_dir,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, target)
        temporary_path = None
        return target
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _ruleset_format_from_extension(extension: str) -> str:
    extension = extension.lower()
    if extension in {"yaml", "yml"}:
        return "yaml"
    if extension in {"mrs"}:
        return "mrs"
    return "text"


def _toggle_user_with_admin(user_id: int, actor_id: int) -> bool:
    """Toggle one ordinary user's enabled state under its lifecycle guard."""
    with _ruleset_user_lock(user_id):
        _reload_admin_actor_locked(actor_id)
        target = get_user_by_id(int(user_id))
        if target is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        if bool(target["is_admin"]):
            raise HTTPException(status_code=403, detail="管理员账号不能在这里启停")
        new_enabled = not bool(target["is_enabled"])
        set_user_enabled(user_id, new_enabled)
        return new_enabled
