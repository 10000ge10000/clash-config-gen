"""节点健康检测：在服务器上临时启动一个 mihomo，真连测试地址判断每个节点是否可用。

判定标准与客户端 url-test 相同：经节点请求固定的测试地址，限时内拿到响应即“可用”。
检测从部署服务器发出，只代表节点服务本身是否在运行，不代表用户本地网络一定能连上。

安全约束：
- 测试地址固定，不读用户配置，避免借 direct 类节点探测内网；
- server 指向本机、内网、链路本地等地址的节点不检测（返回 skipped）；
- mihomo 只开 127.0.0.1 上的控制器（随机端口 + 随机密钥），不开任何代理入站端口；
- 全局并发、单账号互斥、短期缓存，防止被频繁触发。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait

import yaml

LOGGER = logging.getLogger(__name__)

TEST_URL = "https://www.gstatic.com/generate_204"
TEST_TIMEOUT_MS = 5000
STARTUP_TIMEOUT = 8.0
CACHE_SECONDS = 30
RESOLVE_TIMEOUT = 6.0
RESOLVE_WORKERS = 16
SEMAPHORE_WAIT = 20.0
MAX_NODES = 300
HEALTH_GROUP_NAME = "__node_health__"
# 不经过远端服务器、或检测没有意义的类型。
_SKIP_TYPES = {"direct", "reject", "reject-drop", "pass", "dns", "compatible"}
# mihomo 在 -d 目录里会读这些 geodata；软链过去避免启动时下载。
_GEODATA_FILES = ("geoip.metadb", "Country.mmdb", "GeoIP.dat", "GeoSite.dat", "GeoLite2-ASN.mmdb")

_GLOBAL_SEMAPHORE = threading.BoundedSemaphore(2)
_USER_LOCKS: dict[int, threading.Lock] = {}
_USER_LOCKS_GUARD = threading.Lock()
_CACHE: dict[int, tuple[float, str, dict]] = {}


def health_enabled() -> bool:
    flag = os.getenv("NODE_HEALTH_ENABLED", os.getenv("MIHOMO_VALIDATE_ENABLED", "true"))
    if str(flag).strip().lower() in {"0", "false", "no", "off"}:
        return False
    return bool(shutil.which(os.getenv("MIHOMO_BINARY", "mihomo")))


def _is_public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def _hosts_of(proxy: dict) -> list[str]:
    """节点会直接连接的地址：server，以及 WireGuard 的 peers[].server。"""
    hosts = [proxy.get("server")]
    for peer in proxy.get("peers") or []:
        if isinstance(peer, dict):
            hosts.append(peer.get("server"))
    return [str(host or "").strip().strip("[]") for host in hosts if host is not None]


def _literal_ip(host: str):
    try:
        return ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None


def _resolve_all(hosts: list[str], resolve) -> dict:
    """并发解析域名，总时长有上限；解析失败或超时的记为 None。"""
    results = {host: None for host in hosts}
    if not hosts:
        return results

    def lookup(host):
        infos = resolve(host, None)
        return sorted({info[4][0] for info in infos if info and len(info) > 4 and info[4]})

    executor = ThreadPoolExecutor(max_workers=min(RESOLVE_WORKERS, len(hosts)))
    try:
        futures = {executor.submit(lookup, host): host for host in hosts}
        done, _ = wait(futures, timeout=RESOLVE_TIMEOUT)
        for future in done:
            try:
                results[futures[future]] = future.result() or None
            except (OSError, UnicodeError, ValueError):
                results[futures[future]] = None
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return results


_IPV6_STATE = {"checked": 0.0, "available": False}


def ipv6_available() -> bool:
    """服务器（容器）有没有 IPv6 出口。没有路由时 connect 会立即失败；结果缓存 10 分钟。"""
    now = time.monotonic()
    if _IPV6_STATE["checked"] and now - _IPV6_STATE["checked"] < 600:
        return _IPV6_STATE["available"]
    available = False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.connect(("2001:4860:4860::8888", 53))  # UDP connect 只查路由，不发包
            # Docker 开 IPv6 时容器用内部 ULA 地址经 NAT66 出网，源地址不是公网地址；有路由且不是回环、链路本地即可。
            local = ipaddress.ip_address(sock.getsockname()[0].split("%", 1)[0])
            available = not (local.is_loopback or local.is_link_local or local.is_unspecified)
    except OSError:
        available = False
    _IPV6_STATE.update(checked=now, available=available)
    return available


def plan_health_check(proxies: list, groups: list | None = None, resolve=socket.getaddrinfo,
                      ipv6: bool | None = None) -> tuple[dict, list, dict]:
    """返回 (mihomo 配置, 要检测的节点名, 不交给 mihomo 的节点 {名: 原因})。

    原因 private / unsupported / limit / ipv6 表示不检测（ipv6：服务器没有 IPv6 出口，纯 IPv6 节点测不了，
    不能误判为不可用）；unresolved 表示服务器解析不了域名，按不可用处理。
    域名在这里解析一次并用 hosts 固定给 mihomo，mihomo 不再自己解析，DNS rebinding 无法绕过内网过滤。
    """
    candidates_nodes = []
    skipped = {}
    names = set()
    for proxy in (proxies or [])[:MAX_NODES]:
        if not isinstance(proxy, dict):
            continue
        name = str(proxy.get("name") or "").strip()
        if not name or name in names:
            continue
        names.add(name)
        if str(proxy.get("type") or "").lower() in _SKIP_TYPES:
            skipped[name] = "unsupported"
            continue
        hosts = _hosts_of(proxy)
        if not hosts or any(not host or host.lower() == "localhost" or host.lower().endswith(".localhost") for host in hosts):
            skipped[name] = "private"
            continue
        candidates_nodes.append((name, proxy, hosts))
    for proxy in (proxies or [])[MAX_NODES:]:
        if isinstance(proxy, dict) and proxy.get("name"):
            skipped.setdefault(str(proxy["name"]), "limit")

    if ipv6 is None:
        ipv6 = ipv6_available()
    domains = sorted({host for _, _, hosts in candidates_nodes for host in hosts if _literal_ip(host) is None})
    resolved = _resolve_all(domains, resolve)
    if not ipv6:
        # 没有 IPv6 出口：同时有 v4 / v6 的域名只用 IPv4 测；只有 IPv6 的记为空列表，下面按 ipv6 跳过。
        resolved = {host: (None if addresses is None else [a for a in addresses if ":" not in a])
                    for host, addresses in resolved.items()}
    usable = []
    pinned = {}
    for name, proxy, hosts in candidates_nodes:
        reason = ""
        for host in hosts:
            ip = _literal_ip(host)
            if ip is not None:
                if not _is_public_address(host):
                    reason = "private"
                elif ip.version == 6 and not ipv6 and reason != "private":
                    reason = "ipv6"
                continue
            addresses = resolved.get(host)
            if addresses is None:
                reason = reason or "unresolved"
            elif not addresses:
                reason = reason if reason == "private" else "ipv6"
            elif not all(_is_public_address(address) for address in addresses):
                reason = "private"
        if reason:
            skipped[name] = reason
            continue
        for host in hosts:
            if _literal_ip(host) is None:
                pinned[host] = resolved[host] if len(resolved[host]) > 1 else resolved[host][0]
        usable.append(proxy)

    usable_names = [str(proxy["name"]) for proxy in usable]
    # 链式代理会经过 dialer-proxy 指向的节点或策略组，所以保留策略组。统一改成 select（选第一个成员，
    # 回落组即主用），去掉 url / interval：不让用户配置的测速地址进入服务器端的检测。
    builtin = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
    candidates = []
    for group in groups or []:
        if not isinstance(group, dict) or not str(group.get("name") or "").strip() or group.get("use"):
            continue
        candidates.append({"name": str(group["name"]), "type": "select",
                           "proxies": [str(member) for member in group.get("proxies") or []]})
    # 成员只能引用还在的节点或策略组；删掉空组后可能又让别的组失去成员，反复收敛。
    while True:
        targets = set(usable_names) | {group["name"] for group in candidates} | builtin
        changed = False
        next_groups = []
        for group in candidates:
            members = [member for member in group["proxies"] if member in targets]
            if members != group["proxies"]:
                changed = True
            if members:
                next_groups.append({**group, "proxies": members})
            else:
                changed = True
        candidates = next_groups
        if not changed:
            break
    cleaned_groups = candidates
    final_targets = set(usable_names) | {group["name"] for group in cleaned_groups} | builtin
    cleaned_proxies = []
    for proxy in usable:
        proxy = dict(proxy)
        dialer = proxy.get("dialer-proxy")
        if dialer is not None and str(dialer) not in final_targets:
            proxy.pop("dialer-proxy", None)
        cleaned_proxies.append(proxy)
    if usable_names:
        cleaned_groups.append({"name": HEALTH_GROUP_NAME, "type": "select", "proxies": usable_names})
    config = {
        "mode": "rule",
        "log-level": "silent",
        "ipv6": True,
        "hosts": pinned,
        "use-hosts": True,
        "use-system-hosts": False,
        "proxies": cleaned_proxies,
        "proxy-groups": cleaned_groups,
        "rules": ["MATCH,DIRECT"],
    }
    return config, usable_names, skipped


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _controller_get(port: int, secret: str, path: str, timeout: float) -> tuple[int, dict]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Authorization": f"Bearer {secret}"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            return response.status, (json.loads(body) if body.strip() else {})
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def _prepare_home(home: str) -> None:
    source = os.getenv("MIHOMO_HOME", "/app/data/mihomo-home")
    for filename in _GEODATA_FILES:
        path = os.path.join(source, filename)
        if os.path.isfile(path):
            try:
                os.symlink(path, os.path.join(home, filename))
            except OSError:
                pass


def run_mihomo_health(config: dict, names: list) -> dict:
    """启动临时 mihomo，对 HEALTH_GROUP_NAME 组做一次并发测速，返回 {名: True/False}。"""
    if not names:
        return {}
    binary = shutil.which(os.getenv("MIHOMO_BINARY", "mihomo"))
    if not binary:
        raise RuntimeError("找不到 mihomo")
    port = _free_port()
    secret = secrets.token_hex(16)
    config = dict(config)
    config["external-controller"] = f"127.0.0.1:{port}"
    config["secret"] = secret
    home = tempfile.mkdtemp(prefix="node-health-")
    process = None
    try:
        _prepare_home(home)
        config_path = os.path.join(home, "config.yaml")
        with open(config_path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(config, handle, allow_unicode=True, sort_keys=False)
        process = subprocess.Popen(
            [binary, "-d", home, "-f", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while True:
            if process.poll() is not None:
                raise RuntimeError("mihomo 启动失败")
            try:
                status, _ = _controller_get(port, secret, "/version", 1.0)
                if status == 200:
                    break
            except (OSError, ValueError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("mihomo 启动超时")
            time.sleep(0.15)
        query = urllib.parse.urlencode({"url": TEST_URL, "timeout": TEST_TIMEOUT_MS})
        group = urllib.parse.quote(HEALTH_GROUP_NAME, safe="")
        status, delays = _controller_get(port, secret, f"/group/{group}/delay?{query}", TEST_TIMEOUT_MS / 1000 + 10)
        if status != 200 and status not in (503, 504):
            raise RuntimeError(f"mihomo 测速接口返回 {status}")
        alive = {str(name) for name, delay in (delays or {}).items() if isinstance(delay, (int, float)) and delay > 0}
        return {name: name in alive for name in names}
    finally:
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        finally:
            # 临时目录里有带 secret 的配置，无论进程能否回收都要删掉。
            shutil.rmtree(home, ignore_errors=True)


def _user_lock(user_id: int) -> threading.Lock:
    with _USER_LOCKS_GUARD:
        return _USER_LOCKS.setdefault(int(user_id), threading.Lock())


def _strip_internal(proxies: list) -> list:
    return [
        {key: value for key, value in proxy.items() if not str(key).startswith("_")} if isinstance(proxy, dict) else proxy
        for proxy in proxies or []
    ]


def check_user_nodes(user_id: int, proxies: list, groups: list | None, force: bool = False, runner=run_mihomo_health,
                     resolve=None) -> dict:
    """检测一个账号的节点。结果：{"enabled", "checked_at", "results": {名: "ok"|"down"|"skipped"}}。

    同一账号同时只跑一次：另一个请求正在检测时直接返回上次结果并标记 busy，不排队占线程。
    失败结果同样缓存，避免页面反复触发服务器启动 mihomo。
    """
    if not health_enabled():
        return {"enabled": False, "checked_at": 0, "results": {}}
    user_id = int(user_id)
    proxies = _strip_internal(proxies)
    fingerprint = hashlib.sha256(json.dumps([proxies, groups], sort_keys=True, default=str).encode("utf-8")).hexdigest()

    def busy():
        cached = _CACHE.get(user_id)
        payload = dict(cached[2]) if cached else {"enabled": True, "checked_at": 0, "results": {}}
        payload["busy"] = True
        return payload

    lock = _user_lock(user_id)
    if not lock.acquire(blocking=False):
        return busy()
    try:
        cached = _CACHE.get(user_id)
        now = time.time()
        if cached and cached[1] == fingerprint and now - cached[0] < CACHE_SECONDS and (not force or now - cached[0] < 5):
            return cached[2]
        # DNS 解析在全局名额之外进行（并发 + 总超时），不占用别的账号的检测名额。
        config, names, skipped = plan_health_check(proxies, groups, resolve or socket.getaddrinfo)
        if not _GLOBAL_SEMAPHORE.acquire(timeout=SEMAPHORE_WAIT):
            return busy()
        try:
            alive = runner(config, names)
            error = ""
        except Exception as exc:  # 检测失败不影响页面其他功能
            LOGGER.warning("节点健康检测失败: %s", type(exc).__name__)
            alive, error = None, "检测暂时不可用"
        finally:
            _GLOBAL_SEMAPHORE.release()
        if alive is None:
            payload = {"enabled": True, "checked_at": int(time.time()), "error": error, "results": {}}
        else:
            results = {name: "ok" if alive.get(name) else "down" for name in names}
            results.update({name: "down" if reason == "unresolved" else "skipped" for name, reason in skipped.items()})
            reasons = {name: reason for name, reason in skipped.items() if reason != "unresolved"}
            payload = {"enabled": True, "checked_at": int(time.time()), "results": results, "reasons": reasons}
        _CACHE[user_id] = (time.time(), fingerprint, payload)
        return payload
    finally:
        lock.release()
