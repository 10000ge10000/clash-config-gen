"""V2 草稿服务：请求草稿规范化、build_config 复用、校验与发布差异计算。

全部为无副作用的纯计算（不写数据库、不加锁），由 api.py 的路由在用户锁内调用。
"""

import copy
import difflib
import hashlib
import json

import yaml
from fastapi import HTTPException

from api_errors import _safe_error_text
from config_builder import DEFAULT_RULE_TYPE, DUSTINWIN_PROVIDERS_MAP, LEGACY_RULE_TYPES, is_no_base_rule_type
from config_builder import builtin_ruleset_names, rename_legacy_rule_target, rename_legacy_target
from config_builder import build_config, build_yaml, validate_config
from config_defaults import apply_v2_global_defaults, build_default_global_config
from mihomo_validator import validate_with_mihomo
from normalizer import normalize_proxies


MAX_DRAFT_PROXIES = 500
BUILTIN_TARGETS = (
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "Proxy",
    "Domestic",
    "Others",
)


def _merged_global_config(raw_global_config: dict | None, saved_global_config: dict | None = None) -> dict:
    """合并当前草稿的全局设置；完整请求优先，旧账号缺失字段使用默认值。"""
    base = {}
    if raw_global_config is None and isinstance(saved_global_config, dict):
        base.update(saved_global_config)
    elif isinstance(raw_global_config, dict):
        base.update(raw_global_config)
    return apply_v2_global_defaults(build_default_global_config(), base)


def _draft_source(body: dict) -> dict:
    if isinstance(body.get("config"), dict):
        source = copy.deepcopy(body["config"])
    else:
        source = copy.deepcopy(body)
    return source


def _normalize_draft(body: dict, saved_config: dict | None = None) -> tuple[dict, dict]:
    """将旧/新请求收敛到同一份完整 canonical draft，不写入数据库。"""
    source = _draft_source(body)
    saved = saved_config or {}
    if not isinstance(source.get("proxies"), list):
        raise HTTPException(status_code=400, detail="proxies 必须是节点数组")
    if len(source["proxies"]) > MAX_DRAFT_PROXIES:
        raise HTTPException(status_code=413, detail=f"节点数量超过上限 {MAX_DRAFT_PROXIES}")

    raw_proxies: list[dict] = []
    for index, proxy in enumerate(source["proxies"], start=1):
        if not isinstance(proxy, dict):
            raise HTTPException(status_code=400, detail=f"第 {index} 个节点必须是对象")
        raw_proxy = copy.deepcopy(proxy)
        proxy_name = str(raw_proxy.get("name") or "").strip()
        if not proxy_name:
            raise HTTPException(status_code=400, detail=f"第 {index} 个节点 name 不能为空")
        if len(proxy_name) > 128:
            raise HTTPException(status_code=400, detail=f"第 {index} 个节点 name 长度不能超过 128 字符")
        raw_proxies.append(raw_proxy)

    normalized_proxies, proxy_warnings, proxy_errors = normalize_proxies(raw_proxies)
    port_errors = [error for error in proxy_errors if "端口" in str(error)]
    if port_errors:
        # Invalid ports are input errors, not a draft validation state.  Do
        # this before any storage write so PUT/validate/publish cannot retain
        # or publish a malformed replacement node.
        raise HTTPException(status_code=400, detail="；".join(port_errors))

    raw_global = source.get("global_config")
    if raw_global is not None and not isinstance(raw_global, dict):
        raise HTTPException(status_code=400, detail="global_config 必须是对象")
    global_config = _merged_global_config(raw_global, saved.get("global_config"))
    # lhie1 规则源已下线，它的目标覆盖不再有意义。
    global_config.pop("lhie1_provider_targets", None)
    for override_key in ("dustinwin_provider_targets",):
        overrides = global_config.get(override_key)
        if overrides is None:
            continue
        if not isinstance(overrides, dict) or not all(
            isinstance(name, str) and isinstance(target, str) for name, target in overrides.items()
        ):
            raise HTTPException(status_code=400, detail=f"{override_key} 必须是 规则集名 → 策略组名 的对象")
        global_config[override_key] = {name: rename_legacy_target(target) for name, target in overrides.items()}

    custom_rules = source.get("custom_rules", [])
    if custom_rules is None:
        custom_rules = []
    if not isinstance(custom_rules, list):
        raise HTTPException(status_code=400, detail="custom_rules 必须是数组")
    if len(custom_rules) > 500:
        raise HTTPException(status_code=413, detail="自定义规则数量超过上限 500")
    for rule_index, rule in enumerate(custom_rules, start=1):
        if not isinstance(rule, str):
            raise HTTPException(status_code=400, detail="custom_rules 的每项必须是字符串")
        if len(rule) > 512:
            raise HTTPException(status_code=400, detail=f"第 {rule_index} 条规则长度不能超过 512 字符")
    custom_rules = [rename_legacy_rule_target(rule) for rule in custom_rules]

    custom_rule_providers = source.get("custom_rule_providers", {})
    if custom_rule_providers is None:
        custom_rule_providers = {}
    if not isinstance(custom_rule_providers, dict):
        raise HTTPException(status_code=400, detail="custom_rule_providers 必须是对象")
    reserved_names = builtin_ruleset_names()
    for alias, provider in custom_rule_providers.items():
        if not isinstance(provider, dict):
            raise HTTPException(status_code=400, detail="custom_rule_providers 的每项必须是对象")
        if alias in reserved_names:
            raise HTTPException(status_code=400, detail=f"规则集别名 {alias} 与内置规则集重名，请换一个名字")
        target = provider.get("target")
        if target is not None and (not isinstance(target, str) or not target.strip() or "," in target):
            raise HTTPException(status_code=400, detail=f"规则集 {alias} 的目标策略必须是不含逗号的策略组名")
        behavior = provider.get("behavior")
        if behavior is not None and behavior not in ("classical", "domain", "ipcidr"):
            raise HTTPException(status_code=400, detail=f"规则集 {alias} 的 behavior 只能是 classical、domain 或 ipcidr")
        for url_key in ("url", "path"):
            url_value = provider.get(url_key)
            if url_value is not None and not isinstance(url_value, str):
                raise HTTPException(status_code=400, detail=f"规则集 {alias} 的 {url_key} 必须是字符串")
        interval_value = provider.get("interval")
        if interval_value is not None:
            if isinstance(interval_value, bool) or not isinstance(interval_value, int) or not 1 <= interval_value <= 31536000:
                raise HTTPException(status_code=400, detail=f"规则集 {alias} 的 interval 必须是 1-31536000 的整数")
    custom_rule_providers = copy.deepcopy(custom_rule_providers)
    for provider in custom_rule_providers.values():
        if "target" in provider:
            provider["target"] = rename_legacy_target(provider["target"])

    selected_rule_type = source.get("selected_rule_type", DEFAULT_RULE_TYPE)
    if selected_rule_type is None:
        selected_rule_type = DEFAULT_RULE_TYPE
    if not isinstance(selected_rule_type, str):
        raise HTTPException(status_code=400, detail="selected_rule_type 必须是字符串")
    selected_rule_type = selected_rule_type.strip() or DEFAULT_RULE_TYPE
    # lhie1 规则源已并入内置规则，旧草稿保存时迁移过来。
    selected_rule_type = LEGACY_RULE_TYPES.get(selected_rule_type, selected_rule_type)

    import_sources = source.get("import_sources", [])
    if import_sources is None:
        import_sources = []
    if not isinstance(import_sources, list):
        raise HTTPException(status_code=400, detail="import_sources 必须是数组")
    import_sources = copy.deepcopy(import_sources)
    if any(not isinstance(item, dict) for item in import_sources):
        raise HTTPException(status_code=400, detail="import_sources 的每项必须是对象")

    source_counts: dict[str, int] = {}
    for proxy in normalized_proxies:
        source_id = str(proxy.get("_source_id") or "")
        if source_id:
            source_counts[source_id] = source_counts.get(source_id, 0) + 1
    for item in import_sources:
        item["node_count"] = source_counts.get(str(item.get("id") or ""), 0)

    canonical = {
        "proxies": normalized_proxies,
        "global_config": global_config,
        "custom_rules": custom_rules,
        "custom_rule_providers": custom_rule_providers,
        "selected_rule_type": selected_rule_type,
        "import_sources": import_sources,
    }
    return canonical, {
        "warnings": [
            f"节点规范化：{warning}"
            for warning in proxy_warnings
        ],
        "errors": [
            f"节点规范化：{error}"
            for error in proxy_errors
        ],
    }


def _draft_meta_warnings(meta: dict | None) -> list[str]:
    """把规范化阶段的错误也作为 bootstrap 警告展示，避免 GET 配置静默吞掉。"""
    meta = meta or {}
    warnings = [str(item) for item in (meta.get("warnings") or [])]
    warnings.extend(f"草稿校验：{item}" for item in (meta.get("errors") or []))
    return warnings


def _provider_defaults() -> dict:
    return {
        "dustinwin": {
            name: str(config["target"])
            for name, config in DUSTINWIN_PROVIDERS_MAP.items()
        },
    }


def _build_draft_config(draft: dict) -> dict:
    return build_config(
        draft.get("proxies") or [],
        draft.get("global_config") or {},
        draft.get("custom_rules") or [],
        draft.get("custom_rule_providers") or {},
        draft.get("selected_rule_type") or DEFAULT_RULE_TYPE,
    )


def _safe_targets_for_draft(draft: dict, built: dict | None = None) -> tuple[list[str], list[str]]:
    """计算可选目标；``built`` 为同一草稿已构建好的配置时直接复用。

    目标只取决于策略组名与节点名，私有规则集 URL 物化前后不影响结果。
    """
    names = {
        str(proxy.get("name"))
        for proxy in draft.get("proxies", [])
        if isinstance(proxy, dict) and str(proxy.get("name") or "").strip()
    }
    fallback = set(BUILTIN_TARGETS) | names
    try:
        if not isinstance(built, dict):
            built = _build_draft_config(draft)
        group_names = {
            str(group.get("name"))
            for group in built.get("proxy-groups", [])
            if isinstance(group, dict) and str(group.get("name") or "").strip()
        }
        proxy_names = {
            str(proxy.get("name"))
            for proxy in built.get("proxies", [])
            if isinstance(proxy, dict) and str(proxy.get("name") or "").strip()
        }
        return sorted(set(BUILTIN_TARGETS) | group_names | proxy_names), []
    except Exception:
        return sorted(fallback), ["策略组构建失败，已返回内置目标和当前节点名"]


def _draft_signature(draft: dict) -> str:
    canonical_json = json.dumps(
        draft,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _config_stats(built_config: dict | None, draft: dict) -> dict:
    if not isinstance(built_config, dict):
        return {
            "nodes": len(draft.get("proxies") or []),
            "groups": 0,
            "rules": len(draft.get("custom_rules") or []),
            "providers": len(draft.get("custom_rule_providers") or {}),
            "sources": len(draft.get("import_sources") or []),
        }
    return {
        "nodes": len(built_config.get("proxies") or []),
        "groups": len(built_config.get("proxy-groups") or []),
        "rules": len(built_config.get("rules") or []),
        "providers": len(built_config.get("rule-providers") or {}),
        "sources": len(draft.get("import_sources") or []),
    }


def _proxy_names_from_yaml(yaml_text: str) -> list[str]:
    """从配置 YAML 提取 proxies 名称列表（解析失败时返回空，不阻塞 diff）。"""
    if not (yaml_text or "").strip():
        return []
    try:
        parsed = yaml.safe_load(yaml_text)
    except Exception:
        return []
    proxies = parsed.get("proxies") if isinstance(parsed, dict) else None
    if not isinstance(proxies, list):
        return []
    names: list[str] = []
    for proxy in proxies:
        if isinstance(proxy, dict) and proxy.get("name"):
            names.append(str(proxy["name"]))
    return names


def _yaml_diff(draft_yaml: str, published_yaml: str) -> dict:
    draft_lines = draft_yaml.splitlines()
    published_lines = (published_yaml or "").splitlines()
    unified = "\n".join(
        difflib.unified_diff(
            published_lines,
            draft_lines,
            fromfile="published.yaml",
            tofile="draft.yaml",
            lineterm="",
        )
    )
    draft_names = _proxy_names_from_yaml(draft_yaml)
    published_names = _proxy_names_from_yaml(published_yaml)
    published_set = set(published_names)
    draft_set = set(draft_names)
    added = [name for name in draft_names if name not in published_set]
    removed = [name for name in published_names if name not in draft_set]
    return {
        "has_changes": draft_yaml != (published_yaml or ""),
        "published": bool((published_yaml or "").strip()),
        "unified": unified,
        "lines": len(unified.splitlines()) if unified else 0,
        "added_proxies": added,
        "removed_proxies": removed,
    }


def _validation_checks(errors: list[str], warnings: list[str], mihomo_result) -> list[dict]:
    checks = [
        {"status": "error", "label": "结构检查", "detail": _safe_error_text(error)}
        for error in errors
    ]
    checks.extend(
        {"status": "warn", "label": "提示", "detail": _safe_error_text(warning)}
        for warning in warnings
    )
    status = getattr(mihomo_result, "status", "unknown")
    if status != "skipped":
        checks.append(
            {
                "status": "ok" if bool(getattr(mihomo_result, "ok", False)) else "error",
                "label": f"mihomo 内核校验（{status}）",
                "detail": _safe_error_text(getattr(mihomo_result, "message", "")),
            }
        )
    return checks


def _run_validation(draft: dict, published_yaml: str = "", normalization_meta: dict | None = None) -> dict:
    """验证、生成 YAML、计算 targets/signature/diff；不写入数据库。"""
    meta = normalization_meta or {"warnings": [], "errors": []}
    warnings = list(meta.get("warnings") or [])
    errors = list(meta.get("errors") or [])
    node_names = [str(proxy.get("name") or "") for proxy in draft.get("proxies") or []]
    duplicates = sorted({name for name in node_names if name and node_names.count(name) > 1})
    errors.extend(f"节点名称重复：{name}" for name in duplicates)

    built_config = None
    draft_yaml = ""
    mihomo_result = type(
        "ValidationResult",
        (),
        {"status": "skipped", "ok": True, "message": "未启用 mihomo 校验"},
    )()
    try:
        built_config = _build_draft_config(draft)
        draft_yaml = build_yaml(built_config)
        config_errors, config_warnings = validate_config(
            built_config,
            allow_no_match=is_no_base_rule_type(draft.get("selected_rule_type")),
        )
        errors.extend(config_errors)
        warnings.extend(config_warnings)
        mihomo_result = validate_with_mihomo(draft_yaml)
    except Exception:
        errors.append("配置生成失败，请检查节点、规则和全局设置")
        warnings.append("配置生成阶段发生错误，未返回内部异常详情")

    mihomo_ok = bool(getattr(mihomo_result, "ok", False))
    mihomo_status = getattr(mihomo_result, "status", "skipped")
    if mihomo_status == "skipped":
        mihomo_ok = True
    ok = not errors and mihomo_ok
    targets, target_warnings = _safe_targets_for_draft(draft, built_config)
    warnings.extend(target_warnings)
    checks = _validation_checks(errors, warnings, mihomo_result)
    stats = _config_stats(built_config, draft)
    publish_diff = _yaml_diff(draft_yaml, published_yaml)
    return {
        "ok": ok,
        "checks": checks,
        "warnings": warnings,
        "stats": stats,
        "statistics": dict(stats),
        "mihomo": {
            "status": mihomo_status,
            "ok": bool(mihomo_ok),
            "message": _safe_error_text(getattr(mihomo_result, "message", "")),
        },
        "yaml": draft_yaml,
        "draft_signature": _draft_signature(draft),
        "all_targets": targets,
        # `publish_diff` 是 V2 canonical key；`diff` 保留给旧客户端。
        "publish_diff": publish_diff,
        "diff": publish_diff,
        "config": copy.deepcopy(draft),
        "_built_config": built_config,
        "_errors": errors,
    }


def _public_validation(data: dict) -> dict:
    return {key: value for key, value in data.items() if not key.startswith("_")}
