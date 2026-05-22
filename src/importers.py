import base64
import json
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import yaml


REQUIRED_PROXY_FIELDS = {"name", "type", "server", "port"}


def parse_proxy_yaml(raw_text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """解析完整 OpenClash 配置、纯 proxies 列表，或 onekey 输出中的 YAML 节点片段。"""
    if not raw_text or not raw_text.strip():
        raise ValueError("输入内容为空")

    normalized = _extract_yaml_candidate(raw_text)
    loaded = yaml.safe_load(normalized)
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

    return validate_proxies(proxies)


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
    if protocol == "hysteria2":
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
            return "\n".join(lines[idx:]).strip()

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
