import argparse
import os
import sys

from config_builder import DEFAULT_RULE_TYPE, build_config, build_yaml, validate_config
from config_defaults import build_default_global_config
from mihomo_validator import validate_with_mihomo
from storage import (
    init_db,
    list_regular_user_configs,
    publish_user_configs_atomically,
)
from warp_provisioner import WarpProvisionError, provision_warp_masque


def _preset_name() -> str:
    return os.getenv("WARP_PRESET_NAME", "预制masque").strip() or "预制masque"


def _preflight() -> list[dict]:
    users = list_regular_user_configs()
    conflicts = [
        str(user["username"])
        for user in users
        if any(
            isinstance(proxy, dict) and proxy.get("name") == _preset_name()
            for proxy in user.get("proxies") or []
        )
    ]
    if conflicts:
        raise ValueError(
            f"检测到已有同名节点“{_preset_name()}”：{', '.join(conflicts)}；未发起 WARP 注册"
        )
    return users


def backfill(apply: bool) -> int:
    init_db()
    users = _preflight()
    print(f"普通用户待处理数量：{len(users)}")
    if not apply:
        print("预检完成：未发起 WARP 注册、未修改数据库。使用 --apply 执行补齐。")
        return 0
    if not users:
        print("没有需要补齐的普通用户。")
        return 0

    staged_updates: list[dict] = []
    for index, user in enumerate(users, start=1):
        username = str(user["username"])
        print(f"[{index}/{len(users)}] 正在为 {username} 创建独立 WARP MASQUE 注册并校验配置")
        proxy = provision_warp_masque()
        proxies = list(user.get("proxies") or []) + [proxy]
        global_config = dict(user.get("global_config") or build_default_global_config())
        custom_rules = list(user.get("custom_rules") or [])
        custom_rule_providers = dict(user.get("custom_rule_providers") or {})
        selected_rule_type = str(user.get("selected_rule_type") or DEFAULT_RULE_TYPE)
        config = build_config(
            proxies,
            global_config,
            custom_rules=custom_rules,
            custom_rule_providers=custom_rule_providers,
            selected_rule_type=selected_rule_type,
        )
        errors, _warnings = validate_config(config)
        if errors:
            raise ValueError(f"用户 {username} 的完整配置未通过结构检查")
        final_yaml = build_yaml(config)
        validation = validate_with_mihomo(final_yaml)
        if not validation.ok:
            raise ValueError(f"用户 {username} 的完整配置未通过 Mihomo 内核检查")
        staged_updates.append(
            {
                "user_id": user["user_id"],
                "expected_updated_at": user["updated_at"],
                "proxies": proxies,
                "global_config": global_config,
                "custom_rules": custom_rules,
                "custom_rule_providers": custom_rule_providers,
                "import_sources": list(user.get("import_sources") or []),
                "selected_rule_type": selected_rule_type,
                "final_yaml": final_yaml,
            }
        )

    publish_user_configs_atomically(staged_updates)
    print(f"补齐完成：已原子发布 {len(staged_updates)} 位普通用户的订阅。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="为所有普通用户补齐独立 WARP MASQUE 节点")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="发起外部 WARP 注册并在全部校验通过后统一写入数据库",
    )
    args = parser.parse_args()
    try:
        return backfill(args.apply)
    except (ValueError, WarpProvisionError) as exc:
        print(f"补齐失败：{exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"补齐失败：服务暂时不可用（{type(exc).__name__}）", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
