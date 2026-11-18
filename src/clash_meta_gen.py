import yaml
import os

DEFAULT_URL_TEST_URL = "http://cp.cloudflare.com/generate_204"
DEFAULT_URL_TEST_INTERVAL = 60
DEFAULT_URL_TEST_TOLERANCE = 30

# ==========================================
# 安全警告 / Security Warning
# ==========================================
# 这是一个模版文件。
# 为了安全起见，所有服务器地址、密码、UUID 均已替换为示例数据。
# This is a template file. All sensitive data has been replaced with placeholders.

def _example_proxies_data():
    """仅供 main() 示例使用的占位节点数据，不属于生产路径。"""
    return [
        # --------------------------------------
        # 1. Shadowsocks (SS) - 示例
        # --------------------------------------
        {
            "name": "SS-Region-01",
            "type": "ss",
            "server": "ss.example.com",     # 请替换为真实服务器地址
            "port": 8888,                   # 请替换为真实端口
            "cipher": "2022-blake3-aes-128-gcm",
            "password": "replace-with-your-password", # 请替换密码
            "udp": True,
            "ip-version": "dual",
            "plugin": "obfs",
            "plugin-opts": {
                "mode": "tls",
                "host": "bing.com"
            }
        },

        # --------------------------------------
        # 2. Hysteria2 (Hy2) - 示例
        # --------------------------------------
        {
            "name": "Hy2-Region-01",
            "type": "hysteria2",
            "server": "hy2.example.com",
            "port": 443,
            "password": "replace-with-your-auth",
            "sni": "www.bing.com",
            "skip-cert-verify": True,
            "up": "50 Mbps",
            "down": "100 Mbps",
            "alpn": ["h3"],
            "ip-version": "ipv4-prefer"
        },

        # --------------------------------------
        # 3. Tuic - 示例
        # --------------------------------------
        {
            "name": "Tuic-Region-01",
            "type": "tuic",
            "server": "tuic.example.com",
            "port": 8443,
            "uuid": "00000000-0000-0000-0000-000000000000", # 请替换 UUID
            "password": "replace-with-your-password",
            "congestion-controller": "bbr",
            "udp-relay-mode": "native",
            "reduce-rtt": True,
            "alpn": ["h3"],
            "sni": "tuic.example.com"
        },

        # --------------------------------------
        # 4. Trojan / AnyTLS - 示例
        # --------------------------------------
        {
            "name": "Trojan-Region-01",
            "type": "trojan",
            "server": "127.0.0.1",
            "port": 443,
            "password": "replace-with-your-password",
            "sni": "trojan.example.com",
            "udp": True,
            "skip-cert-verify": False,
            "client-fingerprint": "chrome"
        },

        # --------------------------------------
        # 5. Vmess - 示例
        # --------------------------------------
        {
            "name": "Vmess-Region-01",
            "type": "vmess",
            "server": "vmess.example.com",
            "port": 443,
            "uuid": "00000000-0000-0000-0000-000000000000",
            "alterId": 0,
            "cipher": "auto",
            "tls": True,
            "network": "ws",
            "ws-opts": {
                "path": "/",
                "headers": {"Host": "vmess.example.com"}
            }
        },

        # --------------------------------------
        # 6. WireGuard - 示例
        # --------------------------------------
        {
            "name": "WG-Region-01",
            "type": "wireguard",
            "server": "1.2.3.4",
            "port": 51820,
            "ip": "10.0.0.2",
            "private-key": "replace-with-private-key", # 敏感信息
            "public-key": "replace-with-public-key",
            "mtu": 1420,
            "udp": True
        }
    ]

# ==========================================
# 策略组逻辑 (保持原有结构)
# ==========================================

def create_group(name, type_name, proxies_list, extra_proxies=None, url=None, interval=None, disable_udp=False, tolerance=None):
    group = {
        "name": name,
        "type": type_name,
        "proxies": []
    }
    if extra_proxies:
        group["proxies"].extend(extra_proxies)
        
    node_names = [p['name'] for p in proxies_list]
    group["proxies"].extend(node_names)
    
    if url: group["url"] = url
    if interval: group["interval"] = interval
    if disable_udp: group["disable-udp"] = True
    if tolerance and type_name == "url-test": group["tolerance"] = tolerance
    return group

# 基于 QUIC/UDP 传输的协议；其余协议（AnyTLS、VLESS、Trojan、SS 等）按 TCP 处理。
UDP_PROXY_TYPES = {"hysteria2", "hysteria", "tuic", "wireguard"}
DUAL_PROTOCOL_PRIORITIES = ("udp", "tcp")
# 双协议回落组的健康检查超时（毫秒）：UDP 被阻断时尽快判定失败。
DUAL_PROTOCOL_TIMEOUT_MS = 2000
# 常用分组，在策略组列表中紧跟 Proxy（及「单协议节点」）之后。
FRONT_GROUP_NAMES = ("AI Suite", "Global TV")
# 双协议模式下收纳已配对原始节点的子分组，Proxy 里只放这一个入口。
SINGLE_PROTOCOL_GROUP_NAME = "单协议节点"
# 生成器自带的策略组名，VPS 回落组不能与之重名。
RESERVED_GROUP_NAMES = {
    "Auto - UrlTest", "Proxy", "Domestic", "Others", "Microsoft", "AI Suite", "Apple", "Apple TV", "Google",
    "Google FCM", "Scholar", "Bilibili", "Bahamut", "HBO Max", "Pornhub", "Netflix", "Disney Plus",
    "Discovery Plus", "DAZN", "Spotify", "Game", "TikTok", "miHoYo", "Telegram", "Crypto", "Discord",
    "Speedtest", "PayPal", "Youtube", "AdBlock", "Global TV", "Asian TV", "CN Mainland TV",
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL",
}


def _proxy_transport(proxy):
    return "udp" if str(proxy.get("type") or "").lower() in UDP_PROXY_TYPES else "tcp"


# 节点名里的分隔符；右括号类只算断点、保留在组名里（【HK】HY2 → 【HK】）。
_NAME_SEPARATORS = " -_|/·:：（(【[｜丨－—"
_NAME_CLOSERS = "）)】]"


def _is_cjk(char):
    return "\u4e00" <= char <= "\u9fff" or "\u3040" <= char <= "\u30ff" or "\uac00" <= char <= "\ud7af"


def _is_name_boundary(prev_char, next_char):
    """prev_char 与 next_char 之间能否截断：遇到分隔符、右括号或中日韩文字与其他字符的交界。"""
    if next_char is None or next_char in _NAME_SEPARATORS:
        return True
    return prev_char in _NAME_SEPARATORS or prev_char in _NAME_CLOSERS or _is_cjk(prev_char) != _is_cjk(next_char)


def _vps_group_base_name(names, server):
    """取同一 VPS 各节点名的公共前缀作为组名，例如 Ali-1/HK-HY2 与 Ali-1/HK-AnyTLS 得到 Ali-1/HK。

    前缀只在断点处截断：Test-HY2 与 Test-HTTP 得到 Test 而不是 Test-H，香港HY2 与 香港AnyTLS 得到 香港。
    """
    prefix = os.path.commonprefix(names)
    while prefix:
        if len(prefix) == len(os.path.commonprefix(names)):
            next_chars = [name[len(prefix)] if len(name) > len(prefix) else None for name in names]
        else:
            next_chars = [names[0][len(prefix)]]
        if all(_is_name_boundary(prefix[-1], char) for char in next_chars):
            break
        prefix = prefix[:-1]
    prefix = prefix.rstrip(_NAME_SEPARATORS)
    return prefix if len(prefix) >= 2 else server


def _server_key(proxy):
    """配对用的 server：忽略大小写和 IPv6 方括号。"""
    return str(proxy.get("server") or "").strip().strip("[]").lower()


MAX_VPS_GROUP_BASE_LENGTH = 112


def _single_protocol_group_name(taken):
    name = SINGLE_PROTOCOL_GROUP_NAME
    index = 2
    while name in taken:
        name = f"{SINGLE_PROTOCOL_GROUP_NAME} {index}"
        index += 1
    return name


def suggest_dual_protocol_groups(all_proxies, priority="udp", existing_groups=None):
    """合并建议：同一 server 地址上同时有 UDP 类与 TCP 类节点时，建议合成一个 VPS 回落组。

    existing_groups 是用户已确认的 [(组名, 成员)]：其中的节点不再参与建议，组名也不会被复用。
    返回 [(组名, 按优先协议排好序的节点名)]。
    """
    priority = priority if priority in DUAL_PROTOCOL_PRIORITIES else "udp"
    existing_groups = existing_groups or []
    assigned = {member for _name, members in existing_groups for member in members}
    by_server = {}
    order = []
    for proxy in all_proxies:
        if str(proxy.get("name")) in assigned:
            continue
        server = _server_key(proxy)
        if not server:
            continue
        if server not in by_server:
            by_server[server] = []
            order.append(server)
        by_server[server].append(proxy)
    taken = (
        {str(proxy.get("name")) for proxy in all_proxies}
        | RESERVED_GROUP_NAMES
        | {name for name, _members in existing_groups}
    )
    # 先占用「单协议节点」子分组将要使用的名字（与 plan_dual_protocol_groups 的取名规则一致），
    # 保证老账号按建议生成的组名与引入卡片前逐字相同。
    taken.add(_single_protocol_group_name(taken))
    suggestions = []
    for server in order:
        members = by_server[server]
        if {_proxy_transport(proxy) for proxy in members} != {"udp", "tcp"}:
            continue
        names = [str(proxy["name"]) for proxy in members]
        # 组名上限 128 字符，给“ 双协议 N”后缀留出余量。
        base = _vps_group_base_name(names, server)[:MAX_VPS_GROUP_BASE_LENGTH]
        name = base
        if name in taken:
            name = f"{base} 双协议"
        index = 2
        while name in taken:
            name = f"{base} 双协议 {index}"
            index += 1
        taken.add(name)
        ordered = [p for p in members if _proxy_transport(p) == priority] + [
            p for p in members if _proxy_transport(p) != priority
        ]
        suggestions.append((name, [str(p["name"]) for p in ordered]))
    return suggestions


def sanitize_dual_protocol_groups(all_proxies, groups):
    """把用户确认的 VPS 组收敛成可生成的 [(组名, 成员)]。

    成员只保留现有节点、每个节点只属于第一个包含它的组；组名为空或有效成员不足 2 个的组跳过
    （前端会提示“成员不足，不会生成”）。重名等冲突由校验阶段报错，这里不抛异常。
    """
    node_names = {str(proxy.get("name")) for proxy in all_proxies}
    used = set()
    result = []
    for group in groups or []:
        if not isinstance(group, dict):
            continue
        name = str(group.get("name") or "").strip()
        members = []
        for member in group.get("members") or []:
            member = str(member)
            if member in node_names and member not in used and member not in members:
                members.append(member)
        if not name or len(members) < 2:
            continue
        used.update(members)
        result.append((name, members))
    return result


def plan_dual_protocol_groups(all_proxies, priority="udp", explicit_groups=None):
    """双协议回落的分组规划。

    explicit_groups 为用户在节点页确认的 VPS 组（[{name, members}]）；为 None 表示老账号还没确认过，
    沿用按 server 自动合并的建议，输出与确认前一致。

    返回 (vps_groups, auto_members, choice_members, single_group)：
    - vps_groups：[(组名, 成员，第一个为主用)]；
    - auto_members：Auto - UrlTest 的成员，即各 VPS 组加上未合并的节点（确认过的分组按卡片顺序在前）；
    - choice_members：Proxy 与各应用分组的成员，在 auto_members 后追加一个「单协议节点」子分组入口；
    - single_group：(子分组名, 已合并的原始节点名)，没有合并时为 None。
      需要强制某个协议时，先在分组里选子分组，再在子分组里选具体节点，分组本身不再平铺重复节点。
    """
    if explicit_groups is None:
        vps_groups = suggest_dual_protocol_groups(all_proxies, priority)
    else:
        vps_groups = sanitize_dual_protocol_groups(all_proxies, explicit_groups)
    group_of = {member: name for name, members in vps_groups for member in members}

    auto_members = []
    paired_nodes = []
    if explicit_groups is not None:
        # 用户确认过的分组：VPS 组按卡片顺序排在前面，单节点按节点列表顺序排在后面，与节点页一致。
        auto_members = [name for name, _members in vps_groups]
        paired_nodes = [member for _name, members in vps_groups for member in members]
        auto_members += [str(proxy["name"]) for proxy in all_proxies if str(proxy["name"]) not in group_of]
    else:
        for proxy in all_proxies:
            proxy_name = str(proxy["name"])
            if proxy_name in group_of:
                if group_of[proxy_name] not in auto_members:
                    auto_members.append(group_of[proxy_name])
                paired_nodes.append(proxy_name)
            else:
                auto_members.append(proxy_name)
    if not paired_nodes:
        return vps_groups, auto_members, list(auto_members), None
    taken = {str(proxy.get("name")) for proxy in all_proxies} | RESERVED_GROUP_NAMES
    if explicit_groups is not None:
        # 用户确认的组名可能恰好是「单协议节点」，子分组需要避开；自动建议已预先避开。
        taken |= set(group_of.values())
    single_name = _single_protocol_group_name(taken)
    return vps_groups, auto_members, auto_members + [single_name], (single_name, paired_nodes)


def build_single_protocol_group(single_group):
    if not single_group:
        return []
    name, members = single_group
    return [{"name": name, "type": "select", "proxies": list(members)}]


def build_dual_protocol_fallback_groups(vps_groups, url_test_url, url_test_interval):
    return [
        {
            "name": name,
            "type": "fallback",
            "proxies": members,
            "url": url_test_url,
            "interval": url_test_interval,
            "timeout": DUAL_PROTOCOL_TIMEOUT_MS,
            # 空闲时也要定时检查，UDP 被阻断时才能提前切到备用协议。
            "lazy": False,
            # 回落组是自动切换的，面板分组列表里不必单独占一块；仍可在 Proxy 等分组中选中。
            "hidden": True,
        }
        for name, members in vps_groups
    ]


def generate_proxy_groups(
    all_proxies,
    url_test_url=DEFAULT_URL_TEST_URL,
    url_test_interval=DEFAULT_URL_TEST_INTERVAL,
    url_test_tolerance=DEFAULT_URL_TEST_TOLERANCE,
    dual_protocol_priority=None,
    dual_protocol_groups=None,
):
    """dual_protocol_priority 为 "udp"/"tcp" 时启用双协议回落模式，None 时保持原有平铺结构。

    dual_protocol_groups 为用户确认的 VPS 组；None 表示按 server 自动合并。
    """
    groups = []
    vps_groups = []
    auto_proxies = all_proxies
    proxy_choices = all_proxies
    single_group = None
    if dual_protocol_priority:
        vps_groups, auto_members, choice_members, single_group = plan_dual_protocol_groups(
            all_proxies, dual_protocol_priority, dual_protocol_groups
        )
        auto_proxies = [{"name": name} for name in auto_members]
        # Proxy 与各应用/流媒体分组都列合并后的成员（VPS 回落组 + 未配对节点），
        # 再加一个「单协议节点」子分组入口，用于强制指定协议；Auto 只测速合并后的成员。
        proxy_choices = [{"name": name} for name in choice_members]
        all_proxies = proxy_choices

    # 1. 自动测速
    groups.append(create_group("Auto - UrlTest", "url-test", auto_proxies,
                               url=url_test_url, interval=url_test_interval, tolerance=url_test_tolerance))
    
    # 2. 手动选择
    groups.append(create_group("Proxy", "select", proxy_choices,
                               extra_proxies=["Auto - UrlTest", "DIRECT"]))
    groups.extend(build_single_protocol_group(single_group))
    
    # 3. 基础流量规则
    groups.append({"name": "Domestic", "type": "select", "proxies": ["DIRECT", "Proxy"]})
    groups.append({"name": "Others", "type": "select", "proxies": ["Proxy", "DIRECT", "Domestic"]})

    # 4. 应用与流媒体分组 (根据你原本的 Config 还原)
    app_groups = [
        "Microsoft", "AI Suite", "Apple", "Apple TV", "Google", "Google FCM",
        "Scholar", "Bilibili", "Bahamut", "HBO Max", "Pornhub", 
        "Netflix", "Disney Plus", "Discovery Plus", 
        "DAZN", "Spotify", "Game", "TikTok", "miHoYo",
        "Telegram", "Crypto", "Discord", "Speedtest", "PayPal"
    ]
    global_tv_apps = {
        "HBO Max",
        "Netflix",
        "Disney Plus",
        "Discovery Plus",
        "DAZN",
        "Spotify",
    }
    asian_tv_apps = {"Bahamut"}
    mainland_tv_apps = {"Bilibili"}
    # 微软、苹果组承接的是国内可直连的 CDN（microsoft-cn / apple-cn），FCM 推送在国内也可直连，默认直连。
    direct_first_apps = {"Microsoft", "Apple", "Google FCM"}
    for app in app_groups:
        if app in direct_first_apps:
            groups.append(create_group(app, "select", all_proxies, extra_proxies=["DIRECT", "Proxy"]))
        elif app in global_tv_apps:
            groups.append(create_group(app, "select", all_proxies, extra_proxies=["Global TV", "DIRECT", "Proxy"]))
        elif app in asian_tv_apps:
            groups.append(create_group(app, "select", all_proxies, extra_proxies=["Asian TV", "DIRECT", "Proxy"]))
        elif app in mainland_tv_apps:
            groups.append(create_group(app, "select", all_proxies, extra_proxies=["CN Mainland TV", "DIRECT", "Proxy"]))
        else:
            groups.append(create_group(app, "select", all_proxies, extra_proxies=["Proxy", "DIRECT"]))

    # 不能加 disable-udp：mihomo 遇到不支持 UDP 的组会跳过该规则继续匹配，
    # YouTube 的 QUIC 流量就会落到后面的 media 规则，绕开用户在本组的选择。
    groups.append(create_group("Youtube", "select", all_proxies, extra_proxies=["Global TV", "DIRECT", "Proxy"]))

    # 5. 拦截与功能
    groups.append({"name": "AdBlock", "type": "select", "proxies": ["REJECT", "DIRECT", "Proxy"]})
    
    # 电视分组
    groups.append(create_group("Global TV", "select", all_proxies, extra_proxies=["Proxy", "DIRECT"]))
    groups.append(create_group("Asian TV", "select", all_proxies, extra_proxies=["Proxy", "DIRECT"]))
    groups.append({"name": "CN Mainland TV", "type": "select", "proxies": ["DIRECT", "Proxy"]})

    # 6. 双协议回落：每台 VPS 一个 fallback 组，放在最后，不改变既有策略组的顺序。
    # 常用分组前置：紧跟在 Proxy（双协议模式下是「单协议节点」）之后，面板里不用往下翻。
    pinned = [group for name in FRONT_GROUP_NAMES for group in groups if group["name"] == name]
    groups = [group for group in groups if group not in pinned]
    anchor = next(i for i, group in enumerate(groups) if group["name"] == "Proxy") + (2 if single_group else 1)
    groups[anchor:anchor] = pinned

    groups.extend(build_dual_protocol_fallback_groups(vps_groups, url_test_url, url_test_interval))
    return groups

# ==========================================
# 主程序
# ==========================================

def main():
    proxies_data = _example_proxies_data()
    final_config = {
        "port": 7890,
        "socks-port": 7891,
        "mixed-port": 7892,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "external-controller": "0.0.0.0:9090",
        
        # DNS 配置
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "ipv6": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["223.5.5.5", "8.8.8.8"],
            "nameserver": ["https://dns.google/dns-query", "https://223.5.5.5/dns-query"]
        },

        "proxies": proxies_data,
        "proxy-groups": generate_proxy_groups(proxies_data),
        
        # 示例规则
        "rules": [
            "DOMAIN-SUFFIX,google.com,Proxy",
            "DOMAIN-KEYWORD,openai,AI Suite",
            "GEOIP,CN,Domestic",
            "MATCH,Others"
        ]
    }

    # 确保输出目录存在 (适应 Docker 挂载)
    output_path = 'config_meta.yaml'
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(final_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print(f"✅ [Safe Mode] 配置文件已生成: {output_path}")
        print("⚠️  注意：此配置包含示例占位符。请在运行前替换为真实的服务器信息。")
    except Exception as e:
        print(f"❌ 生成失败: {e}")

if __name__ == "__main__":
    main()
