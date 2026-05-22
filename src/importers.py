import base64
import json
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import yaml


REQUIRED_PROXY_FIELDS = {"name", "type", "server", "port"}
SUPPORTED_SHARE_SCHEMES = ("ss://", "trojan://", "vmess://", "vless://", "hysteria2://", "hy2://", "tuic://", "anytls://")


def parse_proxy_yaml(raw_text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """智能解析完整 OpenClash 配置、纯节点列表、onekey 片段、Base64 订阅或 URI 列表。"""
    if not raw_text or not raw_text.strip():
        raise ValueError("输入内容为空")

    _raise_if_html_response(raw_text)

    warnings: list[str] = []
    text = raw_text.strip()

    # onekey 格式检测：直接以 - name: 开头的节点列表（无 proxies: 包裹）
    # 或者以空格开头的 - name:（缩进格式）
    first_nonempty = next((line for line in text.splitlines() if line.strip()), "")
    if first_nonempty.strip().startswith("- name:") or first_nonempty.startswith("  - name:"):
        try:
            # 尝试包装为 proxies 列表
            wrapped = f"proxies:\n{text}"
            loaded = yaml.safe_load(wrapped)
            if loaded and isinstance(loaded, dict) and "proxies" in loaded:
                proxies = loaded["proxies"]
                if isinstance(proxies, list) and proxies:
                    valid, validate_warnings = validate_proxies(proxies)
                    warnings.append("已按 onekey 节点列表格式解析")
                    return valid, warnings + validate_warnings
        except Exception:
            pass  # 继续尝试其他解析方式

    attempts = _build_text_candidates(raw_text)
    errors: list[str] = []

    for label, candidate in attempts:
        try:
            _raise_if_html_response(candidate)
            uri_proxies = _parse_uri_lines(candidate)
            if uri_proxies:
                warnings.append(f"已按 URI 订阅列表解析: {label}")
                return validate_proxies(uri_proxies)

            normalized = _extract_yaml_candidate(candidate)
            try:
                loaded = yaml.safe_load(normalized)
                repaired_used = False
            except Exception:
                normalized = _repair_yaml_text(normalized)
                loaded = yaml.safe_load(normalized)
                repaired_used = True
            if loaded is None:
                raise ValueError("YAML 内容为空")

            if isinstance(loaded, dict):
                proxies = loaded.get("proxies")
                if not isinstance(proxies, list):
                    raise ValueError("完整配置中没有找到 proxies 列表")
            elif isinstance(loaded, list):
                proxies = loaded
            else:
                raise ValueError("YAML 必须是完整配置字典或节点列表")

            valid, validate_warnings = validate_proxies(proxies)
            if repaired_used:
                warnings.append(f"已自动修复缩进后解析: {label}")
            elif label != "原始内容":
                warnings.append(f"已自动修复/转换后解析: {label}")
            return valid, warnings + validate_warnings
        except Exception as exc:
            errors.append(f"{label}: {exc}")

    detail = "\n".join(f"- {item}" for item in errors[-5:])
    raise ValueError(f"无法解析为有效节点。已尝试原文、自动修复、Base64 解码和 URI 列表。\n{detail}")


def normalize_subscription_content(content: str, content_type: str = "") -> str:
    """订阅链接返回内容预处理；HTML 基本代表反代到 Web UI 了。"""
    _raise_if_html_response(content, content_type)
    candidates = _build_text_candidates(content)
    return candidates[0][1] if candidates else content


def validate_proxies(proxies: list[Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """只做安全必要校验，不擅自删除 OpenClash 扩展字段。"""
    valid: list[dict[str, Any]] = []
    warnings: list[str] = []
    seen_names: set[str] = set()

    for index, proxy in enumerate(proxies, start=1):
        if not isinstance(proxy, dict):
            warnings.append(f"第 {index} 个节点不是 YAML 字典，已跳过")
            continue

        missing = REQUIRED_PROXY_FIELDS - set(proxy.keys())
        if missing:
            warnings.append(f"节点 {proxy.get('name', index)} 缺少字段: {', '.join(sorted(missing))}，已跳过")
            continue

        try:
            port = int(proxy["port"])
        except Exception:
            warnings.append(f"节点 {proxy['name']} 的端口不是数字，已跳过")
            continue

        if not 1 <= port <= 65535:
            warnings.append(f"节点 {proxy['name']} 的端口超出 1-65535，已跳过")
            continue

        normalized = dict(proxy)
        normalized["port"] = port

        name = str(normalized["name"])
        if name in seen_names:
            warnings.append(f"导入内容中存在重复节点名 {name}，后续重复项已跳过")
            continue
        seen_names.add(name)

        if normalized.get("type") in {"anytls", "tuic"}:
            warnings.append(f"节点 {name} 使用 {normalized['type']}，请确认你的 OpenClash 内核版本支持该协议")

        valid.append(normalized)

    if not valid:
        raise ValueError("没有解析出任何有效节点")
    return valid, warnings


def parse_share_link(share_link: str) -> dict[str, Any]:
    """解析常见单条分享链接，作为手动导入的补充能力。"""
    parsed = urlparse(share_link.strip())
    protocol = parsed.scheme.lower()
    if protocol == "ss":
        return _parse_ss(parsed, share_link)
    if protocol == "trojan":
        return _parse_trojan(parsed)
    if protocol == "vmess":
        return _parse_vmess(share_link)
    if protocol in {"hysteria2", "hy2"}:
        return _parse_hysteria2(parsed)
    if protocol == "tuic":
        return _parse_tuic(parsed)
    if protocol == "vless":
        return _parse_vless(parsed)
    if protocol == "anytls":
        return _parse_anytls(parsed)
    raise ValueError(f"暂不支持的分享链接协议: {protocol}")


def _extract_yaml_candidate(raw_text: str) -> str:
    lines = raw_text.strip().splitlines()
    for idx, line in enumerate(lines):
        if line.strip() == "proxies:":
            return _dedent_block(lines[idx:]).strip()

    extracted_blocks: list[str] = []
    in_block = False
    base_indent = 0

    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        starts_node = stripped.startswith("- name:") or stripped.startswith("- {")

        if starts_node:
            in_block = True
            base_indent = indent
            extracted_blocks.append(line[base_indent:])
            continue

        if not in_block:
            continue

        if not stripped:
            extracted_blocks.append("")
            continue

        if indent > base_indent:
            extracted_blocks.append(line[base_indent:])
            continue

        in_block = False

    if extracted_blocks:
        return "\n".join(extracted_blocks).strip()
    return raw_text


def _build_text_candidates(raw_text: str) -> list[tuple[str, str]]:
    text = raw_text.strip().replace("\r\n", "\n").replace("\r", "\n")
    candidates: list[tuple[str, str]] = [("原始内容", text)]

    repaired = _repair_yaml_text(text)
    if repaired != text:
        candidates.append(("自动修复缩进", repaired))

    for decoded in _maybe_decode_base64(text):
        candidates.append(("Base64 解码内容", decoded))
        decoded_repaired = _repair_yaml_text(decoded)
        if decoded_repaired != decoded:
            candidates.append(("Base64 解码后自动修复缩进", decoded_repaired))

    extracted = _extract_yaml_candidate(text)
    if extracted != text:
        candidates.append(("提取 YAML 节点片段", extracted))
        extracted_repaired = _repair_yaml_text(extracted)
        if extracted_repaired != extracted:
            candidates.append(("提取节点片段后自动修复缩进", extracted_repaired))

    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for label, value in candidates:
        if value and value not in seen:
            unique.append((label, value))
            seen.add(value)
    return unique


def _repair_yaml_text(raw_text: str) -> str:
    lines = [line.rstrip() for line in raw_text.strip().splitlines()]
    lines = [line for line in lines if not _is_noise_line(line)]
    if not lines:
        return raw_text.strip()

    # 检测并修复 4 空格缩进问题（onekey 常见输出格式）
    # 判断条件：存在以4空格开头但不是8空格的行，且没有以2空格开头的行
    has_4space = any(line.startswith("    ") and not line.startswith("      ") for line in lines if line.strip())
    has_2space = any(line.startswith("  ") and not line.startswith("    ") for line in lines if line.strip())
    if has_4space and not has_2space:
        fixed_lines = []
        for line in lines:
            if not line.strip():
                fixed_lines.append("")
                continue
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            if indent > 0:
                # 将 4 空格缩进转为 2 空格
                new_indent = (indent // 4) * 2 + (indent % 4 // 2)
                fixed_lines.append("  " * new_indent + stripped)
            else:
                fixed_lines.append(line)
        lines = fixed_lines

    if any(line.strip().startswith("- ") for line in lines):
        lines = _dedent_block(lines).splitlines()
        repaired: list[str] = []
        current_base = 0
        for line in lines:
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if stripped.startswith("- "):
                current_base = indent
                repaired.append(line[current_base:])
            elif stripped and repaired and not line.startswith(" ") and ":" in stripped:
                repaired.append("  " + stripped)
            else:
                repaired.append(line[current_base:] if current_base and len(line) >= current_base else line)
        return "\n".join(repaired)

    return _dedent_block(lines).strip()


def _dedent_block(lines: list[str]) -> str:
    non_empty = [line for line in lines if line.strip()]
    if not non_empty:
        return "\n".join(lines)
    min_indent = min(len(line) - len(line.lstrip()) for line in non_empty)
    return "\n".join(line[min_indent:] if len(line) >= min_indent else line for line in lines)


def _is_noise_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    # 原有过滤：OpenClash 输出标记
    if stripped.startswith(("OpenClash YAML 配置", "分享链接", "配置如下", "节点信息", "```")):
        return True
    # 原有过滤：终端符号
    if stripped.startswith(("➜", "✔", "✖", "⚡", "│", "─", "═")):
        return True
    # 新增 onekey 过滤：脚本进度标记和状态输出
    if stripped.startswith(("[*]", "[+]", "[-]", "[OK]", "[ERROR]", "[INFO]")):
        return True
    # 过滤 ANSI 颜色代码开头的行
    if stripped.startswith("\x1b["):
        return True
    return False


def _maybe_decode_base64(text: str) -> list[str]:
    compact = "".join(text.strip().split())
    if len(compact) < 16 or re.search(r"[^A-Za-z0-9+/=_-]", compact):
        return []
    results: list[str] = []
    for candidate in {compact, compact.replace("-", "+").replace("_", "/")}:
        try:
            decoded = base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=False).decode("utf-8")
            if any(marker in decoded for marker in ("proxies:", "ss://", "vmess://", "vless://", "hysteria2://", "tuic://", "anytls://")):
                results.append(decoded)
        except Exception:
            continue
    return results


def _parse_uri_lines(text: str) -> list[dict[str, Any]]:
    proxies: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(SUPPORTED_SHARE_SCHEMES):
            proxies.append(parse_share_link(stripped))
    return proxies


def _raise_if_html_response(text: str, content_type: str = "") -> None:
    head = text.lstrip()[:500].lower()
    if "text/html" in content_type.lower() or head.startswith("<!doctype html") or head.startswith("<html") or "streamlit" in head:
        raise ValueError("订阅地址返回的是 HTML 页面，不是 YAML 订阅。通常是反代把 /sub/ 转发到了 Web UI，请将 /sub/ 和 /health 转发到 FastAPI API 端口 8000。")


def _query(parsed) -> dict[str, str]:
    return {key: values[-1] for key, values in parse_qs(parsed.query).items() if values}


def _parse_ss(parsed, original: str) -> dict[str, Any]:
    raw = original[len("ss://") :].split("#", 1)[0]
    if "@" in raw:
        userinfo, hostport = raw.rsplit("@", 1)
        try:
            method_password = base64.urlsafe_b64decode(_pad_base64(userinfo)).decode("utf-8")
        except Exception:
            method_password = unquote(userinfo)
        method, password = method_password.split(":", 1)
    else:
        decoded = base64.urlsafe_b64decode(_pad_base64(raw)).decode("utf-8")
        method_password, hostport = decoded.rsplit("@", 1)
        method, password = method_password.split(":", 1)
    server, port = hostport.split(":", 1)
    return {
        "name": f"ss-{server}",
        "type": "ss",
        "server": server,
        "port": int(port),
        "cipher": method,
        "password": password,
        "udp": True,
    }


def _parse_trojan(parsed) -> dict[str, Any]:
    password, host = parsed.netloc.split("@", 1)
    server, port = _split_host_port(host, 443)
    params = _query(parsed)
    proxy = {
        "name": f"trojan-{server}",
        "type": "trojan",
        "server": server,
        "port": port,
        "password": unquote(password),
        "udp": True,
    }
    if "sni" in params:
        proxy["sni"] = params["sni"]
    return proxy


def _parse_vmess(share_link: str) -> dict[str, Any]:
    payload = share_link[len("vmess://") :].strip()
    info = json.loads(base64.urlsafe_b64decode(_pad_base64(payload)).decode("utf-8"))
    proxy = {
        "name": info.get("ps") or f"vmess-{info.get('add', 'server')}",
        "type": "vmess",
        "server": info.get("add"),
        "port": int(info.get("port", 443)),
        "uuid": info.get("id"),
        "alterId": int(info.get("aid", 0)),
        "cipher": info.get("scy") or info.get("security") or "auto",
        "network": info.get("net", "tcp"),
        "udp": True,
    }
    if proxy["network"] == "ws":
        proxy["ws-opts"] = {"path": info.get("path") or "/"}
    return proxy


def _parse_hysteria2(parsed) -> dict[str, Any]:
    password, host = parsed.netloc.split("@", 1)
    server, port = _split_host_port(host, 443)
    params = _query(parsed)
    proxy = {
        "name": f"hy2-{server}",
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": unquote(password),
        "sni": params.get("sni", server),
        "skip-cert-verify": params.get("insecure", "0") in {"1", "true"},
        "alpn": ["h3"],
        "udp": True,
    }
    if "mport" in params:
        proxy["ports"] = params["mport"]
        proxy["hop-interval"] = 30
    return proxy


def _parse_tuic(parsed) -> dict[str, Any]:
    userinfo, host = parsed.netloc.split("@", 1)
    uuid, password = userinfo.split(":", 1)
    server, port = _split_host_port(host, 443)
    params = _query(parsed)
    return {
        "name": f"tuic-{server}",
        "type": "tuic",
        "server": server,
        "port": port,
        "uuid": uuid,
        "password": unquote(password),
        "sni": params.get("sni", server),
        "alpn": [params.get("alpn", "h3")],
        "skip-cert-verify": params.get("allow_insecure", "0") in {"1", "true"},
        "reduce-rtt": True,
        "udp-relay-mode": "native",
        "congestion-controller": params.get("congestion_control", "bbr"),
        "udp": True,
    }


def _parse_vless(parsed) -> dict[str, Any]:
    uuid, host = parsed.netloc.split("@", 1)
    server, port = _split_host_port(host, 443)
    params = _query(parsed)
    proxy = {
        "name": f"vless-{server}",
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "network": "tcp",
        "tls": params.get("security") == "reality",
        "udp": True,
    }
    if "flow" in params:
        proxy["flow"] = params["flow"]
    if "sni" in params:
        proxy["servername"] = params["sni"]
    if "fp" in params:
        proxy["client-fingerprint"] = params["fp"]
    if "pbk" in params:
        proxy["reality-opts"] = {"public-key": params["pbk"]}
        if "sid" in params:
            proxy["reality-opts"]["short-id"] = params["sid"]
    return proxy


def _parse_anytls(parsed) -> dict[str, Any]:
    password, host = parsed.netloc.split("@", 1)
    server, port = _split_host_port(host, 443)
    params = _query(parsed)
    alpn = params.get("alpn", "h2,http/1.1")
    return {
        "name": f"anytls-{server}",
        "type": "anytls",
        "server": server,
        "port": port,
        "password": unquote(password),
        "sni": params.get("sni", server),
        "alpn": [item.strip() for item in alpn.split(",") if item.strip()],
        "client-fingerprint": "chrome",
        "skip-cert-verify": params.get("insecure", "0") in {"1", "true"},
        "udp": True,
    }


def _split_host_port(hostport: str, default_port: int) -> tuple[str, int]:
    if ":" not in hostport:
        return hostport, default_port
    host, port = hostport.rsplit(":", 1)
    return host, int(port)


def _pad_base64(value: str) -> bytes:
    cleaned = value.encode("utf-8")
    return cleaned + b"=" * (-len(cleaned) % 4)
