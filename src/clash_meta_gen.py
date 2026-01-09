import yaml
import os

# ==========================================
# 安全警告 / Security Warning
# ==========================================
# 这是一个模版文件。
# 为了安全起见，所有服务器地址、密码、UUID 均已替换为示例数据。
# This is a template file. All sensitive data has been replaced with placeholders.

proxies_data = [
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

def generate_proxy_groups(all_proxies):
    groups = []
    
    # 1. 自动测速
    groups.append(create_group("Auto - UrlTest", "url-test", all_proxies, 
                               url="http://cp.cloudflare.com/generate_204", interval=600, tolerance=50))
    
    # 2. 手动选择
    groups.append(create_group("Proxy", "select", all_proxies, 
                               extra_proxies=["Auto - UrlTest", "DIRECT"]))
    
    # 3. 基础流量规则
    groups.append({"name": "Domestic", "type": "select", "proxies": ["DIRECT", "Proxy"]})
    groups.append({"name": "Others", "type": "select", "proxies": ["Proxy", "DIRECT", "Domestic"]})

    # 4. 应用与流媒体分组 (根据你原本的 Config 还原)
    app_groups = [
        "Microsoft", "AI Suite", "Apple", "Apple TV", "Google FCM", 
        "Scholar", "Bilibili", "Bahamut", "HBO Max", "Pornhub", 
        "Netflix", "Disney Plus", "Discovery Plus", 
        "DAZN", "Spotify", "Steam", "TikTok", "miHoYo",
        "Telegram", "Crypto", "Discord", "Speedtest", "PayPal"
    ]
    for app in app_groups:
        # Bilibili 特殊处理：默认直连
        if app == "Bilibili":
            groups.append(create_group(app, "select", all_proxies, extra_proxies=["CN Mainland TV", "DIRECT", "Proxy"]))
        else:
            groups.append(create_group(app, "select", all_proxies, extra_proxies=["Proxy", "DIRECT"]))

    # Youtube 特殊处理：disable-udp
    groups.append(create_group("Youtube", "select", all_proxies, extra_proxies=["Global TV", "DIRECT", "Proxy"], disable_udp=True))

    # 5. 拦截与功能
    groups.append({"name": "AdBlock", "type": "select", "proxies": ["REJECT", "DIRECT", "Proxy"]})
    groups.append({"name": "HTTPDNS", "type": "select", "proxies": ["REJECT", "DIRECT", "Proxy"]})
    
    # 电视分组
    groups.append(create_group("Global TV", "select", all_proxies, extra_proxies=["Proxy", "DIRECT"]))
    groups.append(create_group("Asian TV", "select", all_proxies, extra_proxies=["Proxy", "DIRECT"]))
    groups.append({"name": "CN Mainland TV", "type": "select", "proxies": ["DIRECT", "Proxy"]})
    
    return groups

# ==========================================
# 主程序
# ==========================================

def main():
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