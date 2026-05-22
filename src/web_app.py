import streamlit as st
import yaml
import requests
import json
import uuid
import os

from auth import get_bool_env
from config_builder import build_yaml as build_subscription_yaml
from importers import parse_proxy_yaml, parse_share_link
from storage import (
    authenticate_user,
    create_user,
    ensure_admin_from_env,
    get_public_base_url,
    get_user_config,
    init_db,
    list_users,
    reset_subscription_token,
    save_user_config,
    set_user_enabled,
)

# ==========================================
# 1. 页面基础设置 (必须位于所有 Streamlit 命令之前)
# ==========================================
st.set_page_config(
    page_title="OpenClash 配置文件生成器", 
    page_icon="⚙️", 
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/MetaCubeX/Clash.Meta',
        'Report a bug': "https://github.com/MetaCubeX/Clash.Meta/issues",
        'About': "### OpenClash 配置文件生成器\n\n这是一个用于快速生成 Clash Meta 配置文件的工具。"
    }
)

# 假设 clash_meta_gen 就在同一目录下，如果报错请确保文件存在
try:
    from clash_meta_gen import generate_proxy_groups 
except ImportError:
    # 如果没有该文件，定义一个临时函数防止报错，方便测试UI
    def generate_proxy_groups(proxies):
        return []

# ==========================================
# 0.5 顶部导航栏 + 隐藏Deploy按钮
# ==========================================
st.markdown("""
<style>
    /* 隐藏 Deploy 按钮 */
    [data-testid="stToolbar"] {
        display: none;
    }
    
    /* 移除顶部默认的 padding */
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 2rem !important;
    }
    
    /* 调整主标题字体大小并确保完整显示 */
    h1 {
        font-size: 2.5rem !important;
        line-height: 1.3 !important;
        margin-bottom: 0.8rem !important;
        white-space: normal !important;
        overflow: visible !important;
        height: auto !important;
        word-break: normal !important;
    }
</style>
""", unsafe_allow_html=True)

st.title("OpenClash 配置文件生成器")
st.markdown("不用手写 YAML，输入节点信息，自动生成符合 Meta 规范的配置文件。")


# ==========================================
# 0.1 数据库初始化 + 登录注册门禁
# ==========================================
init_db()
ensure_admin_from_env()

if "auth_user" not in st.session_state:
    st.session_state.auth_user = None


def render_auth_gate():
    """所有配置都和用户绑定，未登录时必须提前拦截，避免匿名配置丢失。"""
    st.divider()
    login_tab, register_tab = st.tabs(["登录", "注册"])

    with login_tab:
        st.subheader("用户登录")
        with st.form("login_form"):
            username = st.text_input("用户名", key="login_username")
            password = st.text_input("密码", type="password", key="login_password")
            submitted = st.form_submit_button("登录", type="primary", use_container_width=True)
        if submitted:
            user = authenticate_user(username, password)
            if user:
                st.session_state.auth_user = {
                    "id": int(user["id"]),
                    "username": user["username"],
                    "is_admin": bool(user["is_admin"]),
                }
                st.session_state.pop("session_loaded_user_id", None)
                st.rerun()
            else:
                st.error("用户名或密码错误，或账号已被禁用。")

    with register_tab:
        if not get_bool_env("ALLOW_REGISTRATION", True):
            st.warning("当前部署已关闭公开注册，请联系管理员创建账号。")
            return
        st.subheader("注册账号")
        with st.form("register_form"):
            new_username = st.text_input("用户名", key="register_username", help="3-32 位字母、数字、下划线、点或短横线")
            new_password = st.text_input("密码", type="password", key="register_password", help="至少 8 位")
            new_password_confirm = st.text_input("确认密码", type="password", key="register_password_confirm")
            submitted = st.form_submit_button("注册并登录", type="primary", use_container_width=True)
        if submitted:
            if new_password != new_password_confirm:
                st.error("两次输入的密码不一致。")
                return
            try:
                user = create_user(new_username, new_password, is_admin=False)
                st.session_state.auth_user = {
                    "id": int(user["id"]),
                    "username": user["username"],
                    "is_admin": bool(user["is_admin"]),
                }
                st.session_state.pop("session_loaded_user_id", None)
                st.rerun()
            except Exception as exc:
                st.error(f"注册失败: {exc}")


if not st.session_state.auth_user:
    render_auth_gate()
    st.stop()


# ==========================================
# 0. 生产环境级配置常量 (提取自你的 Config)
# ==========================================
# 1. 强力直连兜底规则
DEFAULT_DIRECT_RULES = """## 基础直连规则
DOMAIN-SUFFIX,weather.com,DIRECT
DOMAIN-KEYWORD,testipv6,DIRECT
DOMAIN-KEYWORD,kuxueyun,DIRECT
GEOSITE,category-public-tracker,DIRECT
DOMAIN-SUFFIX,microsoft.com,DIRECT
DOMAIN-SUFFIX,apple.com,DIRECT
DOMAIN,gateway.icloud.com,DIRECT
DOMAIN,metrics.icloud.com,DIRECT
DOMAIN-SUFFIX,dbankcdn.com,DIRECT
DOMAIN-SUFFIX,dbankcloud.cn,DIRECT
DOMAIN-SUFFIX,vsallcity.awsdns-cn-north-1.com.cn,DIRECT

## 国内流媒体与应用直连
DOMAIN-SUFFIX,bilibili.com,DIRECT
DOMAIN-SUFFIX,bilivideo.com,DIRECT
DOMAIN-SUFFIX,douyin.com,DIRECT
DOMAIN-SUFFIX,douyincdn.com,DIRECT
DOMAIN-SUFFIX,huya.com,DIRECT
DOMAIN-SUFFIX,iqiyi.com,DIRECT
DOMAIN-SUFFIX,qq.com,DIRECT
DOMAIN-SUFFIX,tencent.com,DIRECT
DOMAIN-SUFFIX,alicdn.com,DIRECT
DOMAIN-SUFFIX,taobao.com,DIRECT
DOMAIN-SUFFIX,jd.com,DIRECT
DOMAIN-SUFFIX,163.com,DIRECT
DOMAIN-SUFFIX,126.net,DIRECT
DOMAIN-SUFFIX,mgtv.com,DIRECT
DOMAIN-SUFFIX,zhihu.com,DIRECT
DOMAIN-SUFFIX,xhscdn.com,DIRECT

## 下载工具进程直连
PROCESS-NAME,aria2c,DIRECT
PROCESS-NAME,BitComet,DIRECT
PROCESS-NAME,fdm,DIRECT
PROCESS-NAME,NetTransport,DIRECT
PROCESS-NAME,qbittorrent,DIRECT
PROCESS-NAME,Thunder,DIRECT
PROCESS-NAME,transmission-daemon,DIRECT
PROCESS-NAME,transmission-qt,DIRECT
PROCESS-NAME,uTorrent,DIRECT
PROCESS-NAME,WebTorrent,DIRECT
PROCESS-NAME,Folx,DIRECT
PROCESS-NAME,v2ray,DIRECT
PROCESS-NAME,ss-local,DIRECT
PROCESS-NAME,ssr-local,DIRECT
PROCESS-NAME,ss-redir,DIRECT
PROCESS-NAME,trojan-go,DIRECT
PROCESS-NAME,xray,DIRECT
PROCESS-NAME,hysteria,DIRECT
PROCESS-NAME,singbox,DIRECT
PROCESS-NAME,UUBooster,DIRECT

## 局域网与GeoIP
GEOIP,CN,DIRECT,no-resolve
MATCH,Proxy
"""

# 2. Fake-IP 过滤列表 (防止国内应用卡顿)
FAKE_IP_FILTER_LIST = [
    "+.services.googleapis.cn", "+.googleapis.cn", "*.lan", "*.localdomain", "*.example", "*.invalid",
    "*.localhost", "*.test", "*.local", "*.home.arpa", "*.direct", "cable.auth.com",
    "network-test.debian.org", "detectportal.firefox.com", "msftconnecttest.com", "msftncsi.com",
    "localhost.*.weixin.qq.com", "*.blzstatic.cn", "*.126.net", "*.163.com", "*.music.163.com",
    "*.kuwo.cn", "*.kugou.com", "*.y.qq.com", "*.music.migu.cn", "music.migu.cn",
    "+.qq.com", "+.tencent.com", "+.srv.nintendo.net", "*.xboxlive.com", "+.battle.net",
    "proxy.golang.org", "stun.*.*", "heartbeat.belkin.com", "*.linksys.com", "*.router.asus.com",
    "mesu.apple.com", "swscan.apple.com", "swquery.apple.com", "swdownload.apple.com",
    "Mijia Cloud", "+.cmbchina.com", "local.adguard.org", "geosite:cn"
]

# 3. 嗅探配置 (强制嗅探 Netflix 等)
SNIFFER_FORCE_DOMAIN = [
    "+.netflix.com", "+.nflxvideo.net", "+.amazonaws.com", "+.media.dssott.com"
]
SNIFFER_SKIP_DOMAIN = [
    "Mijia Cloud", "dlg.io.mi.com", "+.oray.com", "+.sunlogin.net", "+.push.apple.com"
]

# 初始化session state来存储节点
if 'proxies_data' not in st.session_state:
    st.session_state.proxies_data = []

if 'custom_rules' not in st.session_state:
    st.session_state.custom_rules = []

if 'custom_rule_providers' not in st.session_state:
    st.session_state.custom_rule_providers = {}

if 'global_config' not in st.session_state:
    st.session_state.global_config = {
        # 基础
        "port": 7890,

        "socks_port": 7891,
        "mixed_port": 7893,
        "allow_lan": True,
        "bind_address": "*",
        "mode": "rule",
        "log_level": "info",
        "ipv6_support": True,
        "external_controller": "0.0.0.0:9090",
        "secret": "password",  # 设置默认密码为"password"
        # 性能与网络
        "keep_alive_interval": 15,
        "tcp_concurrent": True,
        "unified_delay": True,
        "find_process_mode": "strict",
        "geodata_mode": True,
        "geodata_loader": "standard",
        # TUN
        "enable_tun": False,
        "tun_stack": "mixed", # 修改为 mixed
        "tun_device": "utun",
        "tun_auto_route": True,
        "tun_auto_detect_interface": True,
        "tun_dns_hijack": True,
        # DNS (参考 Config)
        "enable_dns": True,
        "dns_listen": "0.0.0.0:7874", # 修改为 7874
        "dns_ipv6": True,
        "enhanced_mode": "fake-ip",
        "fake_ip_range": "198.18.0.1/16",
        "default_nameserver": "223.5.5.5\n119.29.29.29",
        "nameserver": "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
        "fallback": "https://1.1.1.1/dns-query\ntcp://8.8.8.8",
        # 嗅探 (默认开启)
        "enable_sniffer": True, 
        "sniff_override_dest": True,
        # 规则
        "custom_rules": DEFAULT_DIRECT_RULES # 注入默认规则
    }

current_user = st.session_state.auth_user
saved_config = get_user_config(current_user["id"])
if st.session_state.get("session_loaded_user_id") != current_user["id"]:
    # 登录后只自动加载一次，避免用户在页面上刚修改的内容被每次 rerun 覆盖。
    if saved_config.get("proxies"):
        st.session_state.proxies_data = saved_config["proxies"]
    if saved_config.get("global_config"):
        st.session_state.global_config.update(saved_config["global_config"])
    if saved_config.get("custom_rules"):
        st.session_state.custom_rules = saved_config["custom_rules"]
    if saved_config.get("custom_rule_providers"):
        st.session_state.custom_rule_providers = saved_config["custom_rule_providers"]
    if saved_config.get("selected_rule_type"):
        st.session_state.selected_rule_type = saved_config["selected_rule_type"]
    st.session_state.session_loaded_user_id = current_user["id"]

# ==========================================
# 2. 侧边栏：认证 + 高级全局设置
# ==========================================
with st.sidebar:
    st.header("账号")
    st.caption(f"当前用户: {current_user['username']}")
    subscription_url = f"{get_public_base_url()}/sub/{saved_config['token']}"
    st.text_input("订阅链接", value=subscription_url, key="subscription_url_view", help="复制到 OpenClash 的订阅地址")
    if st.button("重置订阅 Token", help="旧订阅链接会立即失效，适合链接泄露后的应急处理"):
        reset_subscription_token(current_user["id"])
        st.success("订阅 Token 已重置。")
        st.rerun()
    if st.button("退出登录"):
        st.session_state.clear()
        st.rerun()

    if current_user["is_admin"]:
        with st.expander("用户管理", expanded=False):
            for user in list_users():
                cols = st.columns([2, 1, 1])
                with cols[0]:
                    role = "管理员" if user["is_admin"] else "用户"
                    status = "启用" if user["is_enabled"] else "禁用"
                    st.caption(f"{user['username']} / {role} / {status}")
                with cols[1]:
                    if not user["is_admin"]:
                        target_enabled = not bool(user["is_enabled"])
                        label = "启用" if target_enabled else "禁用"
                        if st.button(label, key=f"toggle_user_{user['id']}"):
                            set_user_enabled(int(user["id"]), target_enabled)
                            st.rerun()
                with cols[2]:
                    if st.button("重置Token", key=f"reset_token_{user['id']}"):
                        reset_subscription_token(int(user["id"]))
                        st.rerun()

    st.divider()
    st.header("全局设置")
    
    # 目标环境选择
    st.info("💡 **请根据您的使用场景选择模式**")
    target_mode = st.radio(
        "生成模式", 
        ("全平台客户端 (PC/移动端)", "OpenClash / 软路由"),
        index=0,
        horizontal=True,
        help="全平台客户端：适用于 Windows, macOS, Android, iOS 等独立运行的客户端，生成包含 TUN、DNS 的完整配置。\nOpenClash：精简配置，仅生成节点和策略，基础设置由插件接管。"
    )
    is_desktop = target_mode == "全平台客户端 (PC/移动端)"

    # --- 基础入站设置 ---
    if is_desktop:
        with st.expander("📡 端口与基础设置", expanded=False):
            col_p1, col_p2 = st.columns(2)
            with col_p1:
                mixed_port = st.number_input("混合端口 (Mixed)", value=st.session_state.global_config["mixed_port"], 
                                             help="同时支持 HTTP 和 SOCKS5 的端口，推荐使用。", key="gc_mixed_port")
                port = st.number_input("HTTP 端口", value=st.session_state.global_config["port"], key="gc_port")
            with col_p2:
                socks_port = st.number_input("Socks 端口", value=st.session_state.global_config["socks_port"], key="gc_socks_port")
                keep_alive = st.number_input("保活间隔 (秒)", value=st.session_state.global_config["keep_alive_interval"], 
                                             help="TCP Keep Alive 间隔，防止长连接中断。", key="gc_keep_alive")

            allow_lan = st.checkbox("允许局域网访问 (Allow LAN)", value=st.session_state.global_config["allow_lan"], 
                                    help="是否允许局域网内的其他设备连接此代理端口。", key="gc_allow_lan")
            
            ipv6_support = st.checkbox("启用 IPv6 支持", value=st.session_state.global_config["ipv6_support"], 
                                       help="是否让核心处理 IPv6 流量。", key="gc_ipv6")

            bind_address = st.text_input("绑定地址", value=st.session_state.global_config["bind_address"], 
                                         help="监听绑定的 IP 地址，'*' 代表绑定所有接口。", key="gc_bind_addr")
    else:
        # 非桌面模式，保持默认值或当前Session值，不显示UI
        mixed_port = st.session_state.global_config["mixed_port"]
        port = st.session_state.global_config["port"]
        socks_port = st.session_state.global_config["socks_port"]
        keep_alive = st.session_state.global_config["keep_alive_interval"]
        allow_lan = st.session_state.global_config["allow_lan"]
        ipv6_support = st.session_state.global_config["ipv6_support"] # OpenClash通常也有IPv6开关，这里隐藏以防冲突
        bind_address = st.session_state.global_config["bind_address"]
        if is_desktop is False: # 仅仅是为了在非桌面模式下加个提示
             st.info("ℹ️ 端口、监听等基础设置已隐藏 (由 OpenClash 全局设置接管)")

    # --- 模式与控制 ---
    if is_desktop:
        with st.expander("🎮 模式与控制", expanded=False):
            mode = st.selectbox("运行模式", ["rule", "global", "direct"], 
                                index=["rule", "global", "direct"].index(st.session_state.global_config["mode"]),
                                help="Rule: 规则分流 (推荐)\nGlobal: 全局代理\nDirect: 直接连接", key="gc_mode")
            
            log_level = st.selectbox("日志级别", ["info", "warning", "error", "debug", "silent"], 
                                     index=["info", "warning", "error", "debug", "silent"].index(st.session_state.global_config["log_level"]),
                                     help="控制日志输出的详细程度，Debug 最详细。", key="gc_log_level")
            
            external_controller = st.text_input("API 监听地址", value=st.session_state.global_config["external_controller"], 
                                                help="外部控制器地址，通常用于连接 Dashboard (如 Yacd/Metacubex)。", key="gc_ext_ctrl")
            
            secret = st.text_input("API 密钥 (Secret)", value=st.session_state.global_config["secret"], type="password", 
                                   help="访问 API 的密码，留空则无密码。", key="gc_secret")

            find_process_mode = st.selectbox("进程匹配模式", ["strict", "always", "off"], 
                                             index=["strict", "always", "off"].index(st.session_state.global_config["find_process_mode"]),
                                             help="控制是否匹配发起请求的进程名。\nStrict (推荐): 严格模式，精准匹配，性能好。\nAlways: 总是匹配，可能误判。\nOff: 关闭此功能。", key="gc_find_proc")
    else:
        # 非桌面模式，隐藏模式与控制设置
        mode = st.session_state.global_config["mode"]
        log_level = st.session_state.global_config["log_level"]
        external_controller = st.session_state.global_config["external_controller"]
        secret = st.session_state.global_config["secret"]
        find_process_mode = st.session_state.global_config["find_process_mode"]

    # --- TUN 模式 ---
    if is_desktop:
        with st.expander("🛡️ TUN 模式 (虚拟网卡)", expanded=False):
            enable_tun = st.checkbox("启用 TUN 模式", value=st.session_state.global_config["enable_tun"], 
                                     help="创建虚拟网卡接管系统所有流量 (VPN模式)。", key="gc_enable_tun")
            
            if enable_tun:
                tun_stack = st.selectbox("协议栈 (Stack)", ["gvisor", "system", "mixed"], 
                                         index=["gvisor", "system", "mixed"].index(st.session_state.global_config["tun_stack"]) if st.session_state.global_config["tun_stack"] in ["gvisor", "system", "mixed"] else 0,
                                         help="System: 系统原生 (快但兼容性一般)\ngVisor: 谷歌用户态 (稳定)\nMixed: 混合模式", key="gc_tun_stack")
                
                tun_device = st.text_input("设备名称", value=st.session_state.global_config["tun_device"], 
                                           help="虚拟网卡的名称，通常为 utun 或 Meta。", key="gc_tun_dev")
                
                tun_auto_route = st.checkbox("自动配置路由", value=st.session_state.global_config["tun_auto_route"], 
                                             help="自动设置系统路由表以转发流量到 TUN。", key="gc_tun_route")
                
                tun_auto_detect_interface = st.checkbox("自动检测接口", value=st.session_state.global_config["tun_auto_detect_interface"], 
                                                        help="自动识别出口网卡。", key="gc_tun_detect")
                
                tun_dns_hijack = st.checkbox("DNS 劫持", value=st.session_state.global_config["tun_dns_hijack"], 
                                             help="强制劫持局域网内的 DNS 请求。", key="gc_tun_hijack")
            else:
                # 定义变量以防未定义
                tun_stack = st.session_state.global_config["tun_stack"]
                tun_device = st.session_state.global_config["tun_device"]
                tun_auto_route = st.session_state.global_config["tun_auto_route"]
                tun_auto_detect_interface = st.session_state.global_config["tun_auto_detect_interface"]
                tun_dns_hijack = st.session_state.global_config["tun_dns_hijack"]

    else:
        # 非桌面模式，隐藏 TUN 设置
        enable_tun = st.session_state.global_config["enable_tun"]
        tun_stack = st.session_state.global_config["tun_stack"]
        tun_device = st.session_state.global_config["tun_device"]
        tun_auto_route = st.session_state.global_config["tun_auto_route"]
        tun_auto_detect_interface = st.session_state.global_config["tun_auto_detect_interface"]
        tun_dns_hijack = st.session_state.global_config["tun_dns_hijack"]

    # --- DNS 设置 ---
    if is_desktop:
        with st.expander("🌐 DNS 设置", expanded=False):
            enable_dns = st.checkbox("启用内置 DNS", value=st.session_state.global_config["enable_dns"], 
                                     help="强烈建议开启，否则无法进行规则分流。", key="gc_enable_dns")
            
            if enable_dns:
                dns_listen = st.text_input("DNS 监听端口", value=st.session_state.global_config["dns_listen"], key="gc_dns_listen")
                
                enhanced_mode = st.selectbox("增强模式", ["fake-ip", "redir-host"], 
                                             index=["fake-ip", "redir-host"].index(st.session_state.global_config["enhanced_mode"]),
                                             help="Fake-IP: 返回假 IP 秒开网页 (推荐)\nRedir-Host: 真实解析 (兼容性更好)", key="gc_dns_mode")
                
                fake_ip_range = st.text_input("Fake-IP 网段", value=st.session_state.global_config["fake_ip_range"], 
                                              help="Fake-IP 模式下使用的虚拟 IP 段。", key="gc_fakeip_range")
                
                st.markdown("---")
                
                # DNS 预设按钮
                st.caption("DNS 快速预设")
                d_col1, d_col2 = st.columns(2)
                with d_col1:
                    if st.button("兼容模式 (UDP)", help="使用 114/AliDNS (非加密)，解决 DoT/DoH 连接失败问题。", use_container_width=True):
                        st.session_state.global_config["default_nameserver"] = ""
                        st.session_state.global_config["nameserver"] = "223.5.5.5\n114.114.114.114"
                        st.session_state.global_config["fallback"] = "8.8.8.8\n1.1.1.1"
                        # 更新 Widget State (如果 key 存在)
                        if "gc_dns_boot" in st.session_state: st.session_state["gc_dns_boot"] = ""
                        if "gc_dns_main" in st.session_state: st.session_state["gc_dns_main"] = "223.5.5.5\n114.114.114.114"
                        if "gc_dns_fallback" in st.session_state: st.session_state["gc_dns_fallback"] = "8.8.8.8\n1.1.1.1"
                        st.rerun()

                with d_col2:
                    if st.button("路由器/本地", help="使用 dhcp:// 或本地网关，适用于 OpenClash/路由器环境。", use_container_width=True):
                        st.session_state.global_config["default_nameserver"] = ""
                        st.session_state.global_config["nameserver"] = 'dhcp://"pppoe-wan"\ndhcp://"eth0"\n223.5.5.5'
                        st.session_state.global_config["fallback"] = ""
                         # 更新 Widget State
                        if "gc_dns_boot" in st.session_state: st.session_state["gc_dns_boot"] = ""
                        if "gc_dns_main" in st.session_state: st.session_state["gc_dns_main"] = 'dhcp://"pppoe-wan"\ndhcp://"eth0"\n223.5.5.5'
                        if "gc_dns_fallback" in st.session_state: st.session_state["gc_dns_fallback"] = ""
                        st.rerun()

                default_nameserver = st.text_area("Bootstrap DNS (默认)", value=st.session_state.global_config["default_nameserver"], height=68,
                                                  help="用于解析 DoH/DoT 域名的传统 DNS 服务器。", key="gc_dns_boot")
                
                nameserver = st.text_area("主要 Nameserver", value=st.session_state.global_config["nameserver"], height=100,
                                          help="核心 DNS 服务器，支持 DoH/DoT/QUIC。", key="gc_dns_main")
                
                fallback = st.text_area("Fallback (回退)", value=st.session_state.global_config["fallback"], height=68,
                                        help="当启用 fallback-filter 时使用的备用 DNS。", key="gc_dns_fallback")
                
                # 增加 Nameserver Policy 支持
                st.markdown("---")
                st.caption("Nameserver Policy (指定域名走特定DNS)")
                nameserver_policy = st.text_area("策略 DNS (格式: 'geosite:cn': https://223.5.5.5/dns-query)", 
                                                 value=st.session_state.global_config.get("nameserver_policy", ""), 
                                                 height=100,
                                                 help="为特定域名指定 DNS 服务器。一行一条。", key="gc_dns_policy")
            else:
                 # 定义变量以防未定义
                dns_listen = st.session_state.global_config["dns_listen"]
                enhanced_mode = st.session_state.global_config["enhanced_mode"]
                fake_ip_range = st.session_state.global_config["fake_ip_range"]
                default_nameserver = st.session_state.global_config["default_nameserver"]
                nameserver = st.session_state.global_config["nameserver"]
                fallback = st.session_state.global_config["fallback"]
                nameserver_policy = st.session_state.global_config.get("nameserver_policy", "")
                
    else:
        # 非桌面模式，隐藏 DNS 设置
        enable_dns = st.session_state.global_config["enable_dns"]
        dns_listen = st.session_state.global_config["dns_listen"]
        enhanced_mode = st.session_state.global_config["enhanced_mode"]
        fake_ip_range = st.session_state.global_config["fake_ip_range"]
        default_nameserver = st.session_state.global_config["default_nameserver"]
        nameserver = st.session_state.global_config["nameserver"]
        fallback = st.session_state.global_config["fallback"]
        nameserver_policy = st.session_state.global_config.get("nameserver_policy", "")

    # --- 核心特性 ---
    # 在非桌面模式(软路由)下直接平铺，去掉折叠框
    core_container = st.expander("⚡ Meta 核心特性", expanded=False) if is_desktop else st.container()
    
    with core_container:
        tcp_concurrent = st.checkbox("TCP 并发 (Concurrent)", value=st.session_state.global_config["tcp_concurrent"], 
                                     help="向所有目标 IP 并发连接，使用最快的握手连接。", key="gc_tcp_conc")
        
        unified_delay = st.checkbox("统一延迟计算", value=st.session_state.global_config["unified_delay"], 
                                    help="去除握手等额外的延迟时间，仅计算传输延迟。", key="gc_uni_delay")
        
        geodata_mode = st.checkbox("GeoData 模式", value=st.session_state.global_config["geodata_mode"], 
                                   help="使用 .dat 文件代替 mmdb，减小内存占用。", key="gc_geodata")
        
        enable_sniffer = st.checkbox("启用流量嗅探 (Sniffer)", value=st.session_state.global_config["enable_sniffer"], 
                                     help="准确识别域名，解决由 IP 访问导致的规则失效问题。", key="gc_sniffer")
        
        sniff_override = st.checkbox("嗅探覆盖目标", value=st.session_state.global_config["sniff_override_dest"], 
                                     help="使用嗅探到的域名覆盖目标 IP，主要用于 Fake-IP 模式。", key="gc_sniff_override")

# 更新 Session State
updated_secret = st.session_state.get('gc_secret', st.session_state.global_config["secret"])
st.session_state.global_config.update({
    "port": port, "socks_port": socks_port, "mixed_port": mixed_port,
    "allow_lan": allow_lan, "bind_address": bind_address, "mode": mode,
    "log_level": log_level, "ipv6_support": ipv6_support,
    "external_controller": external_controller, "secret": updated_secret,
    "keep_alive_interval": keep_alive, "tcp_concurrent": tcp_concurrent,
    "enable_tun": enable_tun, "unified_delay": unified_delay, "find_process_mode": find_process_mode,
    "geodata_mode": geodata_mode, "enable_sniffer": enable_sniffer, "sniff_override_dest": sniff_override
})

if enable_dns:
    # 尝试解析 nameserver_policy
    dns_policy_dict = {}
    if enable_dns and 'nameserver_policy' in locals(): # 确保变量存在
        try:
            raw_policy = nameserver_policy.strip()  # 使用上面定义的 nameserver_policy 变量
            if raw_policy:
                # 简单解析：每行作为一个条目，这里存为字符串，在生成时再处理
                st.session_state.global_config["nameserver_policy"] = raw_policy
        except Exception:
             st.session_state.global_config["nameserver_policy"] = ""

    st.session_state.global_config.update({
        "dns_listen": dns_listen, "enhanced_mode": enhanced_mode,
        "fake_ip_range": fake_ip_range, "default_nameserver": default_nameserver,
        "nameserver": nameserver, "fallback": fallback
    })
else:
    # 即使关闭 DNS，也要确保 key 存在防止报错
    if "nameserver_policy" not in st.session_state.global_config:
        st.session_state.global_config["nameserver_policy"] = ""

if enable_tun:
    st.session_state.global_config.update({
        "tun_stack": tun_stack, "tun_device": tun_device,
        "tun_auto_route": tun_auto_route, "tun_auto_detect_interface": tun_auto_detect_interface,
        "tun_dns_hijack": tun_dns_hijack
    })

if enable_dns:
    st.session_state.global_config.update({
        "dns_listen": dns_listen, "enhanced_mode": enhanced_mode,
        "fake_ip_range": fake_ip_range, "default_nameserver": default_nameserver,
        "nameserver": nameserver, "fallback": fallback
    })

# ==========================================
# 3. 主界面：节点录入 (完整功能)
# ==========================================
tab1, tab2, tab3, tab4 = st.tabs(["快速填入 (YAML/链接)", "节点管理", "分流规则", "生成与检查"])

with tab1:
    st.info("直接将你的机场或自建节点的 `proxies:` 部分粘贴在下面，或通过订阅链接/分享链接导入。")
    default_yaml = """
- name: "示例节点-SS"
  type: ss
  server: "1.2.3.4"
  port: 8888
  cipher: "aes-128-gcm"
  password: "your_password"
  udp: true
"""

    # 添加通过链接导入的功能
    import_method = st.radio(
        "选择导入方式",
        ("OpenClash/onekey YAML", "分享链接", "订阅链接", "粘贴YAML"),
        help="onekey 脚本输出的 OpenClash YAML 片段、完整配置、纯节点列表都可以直接导入。",
    )
    
    if import_method in ("粘贴YAML", "OpenClash/onekey YAML"):
        raw_yaml_input = st.text_area(
            "粘贴 YAML / OpenClash 节点片段",
            value=default_yaml.strip(),
            height=300,
            help="支持完整 config.yaml、proxies: 段、纯 - name 节点列表，以及 onekey.sh 打印出的 OpenClash YAML 配置。",
        )
    elif import_method == "订阅链接":
        subscription_url = st.text_input("输入订阅链接", placeholder="https://example.com/subscribe/...", help="输入Base64编码的订阅链接")
        raw_yaml_input = ""
        if subscription_url:
            try:
                response = requests.get(subscription_url)
                if response.status_code == 200:
                    # 尝试解析响应为YAML/JSON格式
                    try:
                        import base64
                        # 尝试作为Base64编码的订阅链接处理
                        decoded_content = base64.b64decode(response.text).decode('utf-8')
                        raw_yaml_input = decoded_content
                    except:
                        # 如果不是Base64，则直接使用响应内容
                        raw_yaml_input = response.text
                    st.success("订阅链接获取成功！")
                else:
                    st.error(f"获取订阅链接失败: 状态码 {response.status_code}")
            except Exception as e:
                st.error(f"获取订阅链接失败: {e}")
    else:  # 分享链接
        share_link = st.text_input("输入分享链接", placeholder="ss://, trojan://, vmess:// 等分享链接", help="输入ss://, trojan://, vmess://等分享链接")
        raw_yaml_input = ""
        if share_link:
            try:
                # 解析分享链接并转换为 YAML 格式
                from urllib.parse import unquote, urlparse
                import base64
                
                parsed = urlparse(share_link)
                protocol = parsed.scheme
                
                if protocol == 'ss':
                    # 解析Shadowsocks链接
                    data = unquote(parsed.netloc + parsed.path)
                    if '@' in data:
                        # AEAD格式: method:password@server:port
                        method_password, server_port = data.split('@')
                        method, password = method_password.split(':', 1)
                        server, port = server_port.split(':', 1)
                        
                        proxy = {
                            "name": f"SS-{server}",
                            "type": "ss",
                            "server": server,
                            "port": int(port),
                            "cipher": method,
                            "password": password
                        }
                    else:
                        # 旧格式: base64(method:password)@server:port
                        encoded, server_port = data.split('@')
                        decoded = base64.b64decode(encoded + '=' * (4 - len(encoded) % 4)).decode()
                        method, password = decoded.split(':', 1)
                        server, port = server_port.split(':', 1)
                        
                        proxy = {
                            "name": f"SS-{server}",
                            "type": "ss",
                            "server": server,
                            "port": int(port),
                            "cipher": method,
                            "password": password
                        }
                    
                    raw_yaml_input = yaml.dump([proxy], default_flow_style=False, allow_unicode=True)
                    st.success("Shadowsocks链接解析成功！")
                
                elif protocol == 'trojan':
                    # 解析Trojan链接
                    password_and_host = parsed.netloc
                    password, host = password_and_host.split('@', 1)
                    server, port_str = host.split(':', 1) if ':' in host else (host, '443')
                    port = int(port_str)
                    
                    # 解析查询参数
                    query_params = {}
                    if parsed.query:
                        for param in parsed.query.split('&'):
                            key, value = param.split('=', 1) if '=' in param else (param, '')
                            query_params[key] = unquote(value)
                    
                    proxy = {
                        "name": f"Trojan-{server}",
                        "type": "trojan",
                        "server": server,
                        "port": port,
                        "password": unquote(password)
                    }
                    
                    if 'sni' in query_params:
                        proxy["sni"] = query_params['sni']
                    if 'alpn' in query_params:
                        proxy["alpn"] = query_params['alpn'].split(',')
                    if 'skip-cert-verify' in query_params:
                        proxy["skip-cert-verify"] = query_params['skip-cert-verify'].lower() == 'true'
                    
                    raw_yaml_input = yaml.dump([proxy], default_flow_style=False, allow_unicode=True)
                    st.success("Trojan链接解析成功！")
                
                elif protocol == 'vmess':
                    # 解析VMess链接
                    try:
                        # VMess链接是base64编码的JSON
                        decoded = base64.b64decode(share_link[8:])  # 移除"vmess://"前缀
                        vmess_info = json.loads(decoded.decode())
                        
                        proxy = {
                            "name": vmess_info.get("ps", f"VMess-{vmess_info.get('add', 'server')}"),
                            "type": "vmess",
                            "server": vmess_info.get("add", "server"),
                            "port": int(vmess_info.get("port", 443)),
                            "uuid": vmess_info.get("id", ""),
                            "alterId": int(vmess_info.get("aid", 0)),
                            "cipher": vmess_info.get("scy", "auto")
                        }
                        
                        # 根据network类型设置传输协议
                        net_type = vmess_info.get("net", "tcp")
                        proxy["network"] = net_type
                        
                        # TLS设置
                        if vmess_info.get("tls", "") == "tls":
                            proxy["tls"] = True
                        
                        # 根据传输协议添加额外选项
                        if net_type == "ws":
                            ws_opts = {}
                            if "path" in vmess_info:
                                ws_opts["path"] = vmess_info["path"]
                            if "host" in vmess_info:
                                ws_opts["headers"] = {"Host": vmess_info["host"]}
                            proxy["ws-opts"] = ws_opts
                        elif net_type == "h2":
                            if "path" in vmess_info:
                                proxy["h2-opts"] = {"path": vmess_info["path"]}
                        
                        raw_yaml_input = yaml.dump([proxy], default_flow_style=False, allow_unicode=True)
                        st.success("VMess链接解析成功！")
                    except Exception as e:
                        st.error(f"VMess链接解析失败: {e}")
                
                elif protocol in ("vless", "tuic", "hysteria2", "anytls"):
                    proxy = parse_share_link(share_link)
                    raw_yaml_input = yaml.dump([proxy], default_flow_style=False, allow_unicode=True)
                    st.success(f"{protocol} 链接解析成功！")

                else:
                    st.error(f"不支持的协议类型: {protocol}")
                    
            except Exception as e:
                st.error(f"分享链接解析失败: {e}")

    # 添加导入按钮
    if st.button("导入节点", key="import_proxies", help="导入当前输入的节点"):
        if not raw_yaml_input:
            st.error("没有可导入的内容。")
        else:
            try:
                input_proxies, import_warnings = parse_proxy_yaml(raw_yaml_input)
                existing_names = {proxy.get("name") for proxy in st.session_state.proxies_data}
                new_proxies = []
                for proxy in input_proxies:
                    if proxy["name"] in existing_names:
                        st.warning(f"节点 '{proxy['name']}' 已存在，跳过重复添加")
                        continue
                    new_proxies.append(proxy)
                    existing_names.add(proxy["name"])

                st.session_state.proxies_data.extend(new_proxies)
                st.success(f"成功添加 {len(new_proxies)} 个新节点。")
                for warning in import_warnings:
                    st.warning(warning)
            except Exception as e:
                st.error(f"导入失败: {e}")

with tab2:
    st.write("手动添加单个节点：")
    
    # 节点类型选择
    node_type = st.selectbox("选择节点类型", ["ss", "vless", "vmess", "trojan", "anytls", "tuic", "hysteria2"], help="选择要添加的代理节点类型")
    
    # 通用字段
    col1, col2 = st.columns(2)
    with col1:
        node_name = st.text_input("节点名称", f"My-{node_type.title()}", help="给节点起一个便于识别的名称")
        node_server = st.text_input("服务器地址", "example.com", help="代理服务器的地址")
    with col2:
        node_port = st.number_input("端口", 443, help="代理服务器的端口号")
        if node_type not in ["tuic", "hysteria2"]:  # tuic和hy2协议有单独的配置或不需要此通用UDP开关
            node_udp = st.checkbox("UDP 支持", value=True, key=f"node_udp_{node_type}", help="是否启用UDP转发")
    
    # 根据节点类型显示不同的配置选项
    if node_type == "vmess":
        col3, col4 = st.columns(2)
        with col3:
            node_uuid = st.text_input("UUID", "your-uuid-here", help="VMess协议的用户UUID")
            node_alterid = st.number_input("Alter ID", 0, help="VMess协议的额外ID数量")
            vmess_encryption = st.selectbox("加密方式", ["auto", "none", "aes-128-gcm", "chacha20-poly1305"], index=0, help="VMess协议的加密方式")
        with col4:
            node_tls = st.checkbox("启用TLS", value=True, key=f"node_tls_{node_type}", help="是否启用TLS加密")
            node_skip_cert = st.checkbox("跳过证书验证", value=False, key=f"node_skip_cert_{node_type}", help="是否跳过TLS证书验证")
            node_tfo = st.checkbox("TFO", value=False, key=f"node_tfo_{node_type}", help="是否启用TCP Fast Open")
            
        network_type = st.selectbox("传输协议", ["tcp", "kcp", "ws", "h2", "grpc", "http"], index=0, help="VMess协议的传输方式")
        ip_version = st.selectbox("IP Version", ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"], index=0, help="使用的IP协议版本，默认不设置")
        
        if network_type == "ws":
            ws_path = st.text_input("WebSocket路径", "/", help="WebSocket的路径")
            ws_host = st.text_input("WebSocket主机", "example.com", help="WebSocket的主机头")
        elif network_type == "h2":
            h2_path = st.text_input("HTTP/2路径", "/", help="HTTP/2的路径")
            h2_host = st.text_input("HTTP/2主机", "example.com", help="HTTP/2的主机头")
        elif network_type == "grpc":
            grpc_service_name = st.text_input("gRPC服务名称", "example", help="gRPC服务的名称")
    
    elif node_type == "ss":
        col3, col4 = st.columns(2)
        with col3:
            ss_encryption = st.selectbox("加密方式", [
                "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", 
                "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
                "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
            ], index=0, help="Shadowsocks协议的加密方式")
            node_password = st.text_input("密码", type="password", help="Shadowsocks协议的密码")
        with col4:
            ss_udp_over_tcp = st.checkbox("udp-over-tcp", value=False, key=f"ss_udp_over_tcp_{node_type}", help="是否启用UDP over TCP")
            ss_tfo = st.checkbox("TFO", value=False, key=f"ss_tfo_{node_type}", help="是否启用TCP Fast Open")
        
        ss_network = st.selectbox("传输协议", ["tcp", "kcp", "ws", "h2", "grpc"], index=0, help="传输层协议")
        ss_ip_version = st.selectbox("IP Version", ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"], index=0, help="使用的IP协议版本，默认不设置")
        ss_mux = st.checkbox("多路复用", value=False, key=f"ss_mux_{node_type}", help="是否启用多路复用")
    
    elif node_type == "trojan":
        col3, col4 = st.columns(2)
        with col3:
            node_password = st.text_input("密码", type="password", help="Trojan协议的密码")
            trojan_udp_over_tcp = st.checkbox("udp-over-tcp", value=False, key=f"trojan_udp_over_tcp_{node_type}", help="是否启用UDP over TCP")
        with col4:
            trojan_tfo = st.checkbox("TFO", value=False, key=f"trojan_tfo_{node_type}", help="是否启用TCP Fast Open")
            
        trojan_network = st.selectbox("传输协议", ["tcp", "ws", "grpc"], index=0, help="传输层协议")
        trojan_ip_version = st.selectbox("IP Version", ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"], index=0, help="使用的IP协议版本，默认不设置")

        if trojan_network == "ws":
            ws_path = st.text_input("WebSocket路径", "/", help="WebSocket的路径")
            ws_host = st.text_input("WebSocket主机", "example.com", help="WebSocket的主机头")
        elif trojan_network == "grpc":
            grpc_service_name = st.text_input("gRPC服务名称", "example", help="gRPC服务的名称")
    
    elif node_type == "hysteria2":
        col3, col4 = st.columns(2)
        with col3:
            node_password = st.text_input("密码", type="password", help="Hysteria2协议的认证密码")
            hy2_sni = st.text_input("SNI", "example.com", help="TLS握手时的服务器名称指示")
            hy2_obfs_type = st.selectbox("混淆插件", ["none", "salamander"], index=0, help="流量混淆类型")
        with col4:
            hy2_up_mbps = st.number_input("上行链路容量（默认：Mbps）", 50, help="上行带宽限制")
            hy2_down_mbps = st.number_input("下行链路容量（默认：Mbps）", 100, help="下行带宽限制")
            if hy2_obfs_type != "none":
                hy2_obfs_password = st.text_input("混淆密码", type="password", help="流量混淆密码")
            else:
                 hy2_obfs_password = ""
        
        hy2_skip_cert = st.checkbox("跳过证书验证", value=True, key=f"hy2_skip_cert_{node_type}", help="是否跳过TLS证书验证")
        hy2_alpn = st.selectbox("ALPN", ["h3", "h3-29", "h3-27"], index=0, help="应用层协议协商标识")
        
        enable_port_hopping = st.checkbox("启用端口跳跃", key=f"enable_port_hopping_{node_type}", help="是否启用动态端口跳跃")
        if enable_port_hopping:
            port_hopping_range = st.text_input("端口范围", "20000-40000", help="端口跳跃的范围")
        
        enable_protocol = st.checkbox("启用传输协议设置", key=f"enable_protocol_{node_type}", help="是否自定义传输协议")
        if enable_protocol:
            hy2_protocol = st.selectbox("传输协议", ["udp"], index=0, help="使用的传输协议")
        
        enable_quic_params = st.checkbox("QUIC 参数", key=f"enable_quic_params_{node_type}", help="是否自定义QUIC参数")
        if enable_quic_params:
            with st.expander("QUIC 参数设置"):
                # QUIC 参数计算器
                st.markdown("##### 🛠️ QUIC 参数计算器")
                st.caption("基于带宽和延迟推荐窗口大小 (BDP模型)")
                q_col1, q_col2, q_col3 = st.columns([2, 2, 1])
                with q_col1:
                    calc_bw = st.number_input("带宽 (Mbps)", value=1000, min_value=1, step=10, key="quic_calc_bw")
                with q_col2:
                    calc_rtt = st.number_input("延迟 RTT (ms)", value=50, min_value=1, step=10, key="quic_calc_rtt")
                with q_col3:
                    st.write("")
                    st.write("") 
                    calc_btn = st.button("计算并推荐", key="quic_calc_btn")
                
                # 初始化或获取 session state 中的值
                if 'quic_params_vals' not in st.session_state:
                     st.session_state.quic_params_vals = {
                         "init_stream": 8388608,
                         "max_stream": 8388608,
                         "init_conn": 20971520, 
                         "max_conn": 20971520
                     }

                if calc_btn:
                    # BDP (bytes) = (Bandwidth_Mbps * 10^6 * RTT_ms * 10^-3) / 8
                    # 简化: BDP = Bandwidth * RTT * 125
                    bdp = int(calc_bw * calc_rtt * 125)
                    # 推荐值策略：
                    # init_stream ~= BDP (min 2MB)
                    # max_stream ~= BDP * 1.5
                    # init_conn ~= BDP * 2
                    # max_conn ~= BDP * 4 (或更高)
                    
                    rec_stream = max(2097152, bdp) # 至少 2MB
                    
                    st.session_state.quic_params_vals["init_stream"] = rec_stream
                    st.session_state.quic_params_vals["max_stream"] = int(rec_stream * 1.5)
                    st.session_state.quic_params_vals["init_conn"] = int(rec_stream * 2.5) # 给连接更多余量
                    st.session_state.quic_params_vals["max_conn"] = int(rec_stream * 4)
                    st.success(f"已根据 {calc_bw}Mbps / {calc_rtt}ms 推荐参数 (BDP: {bdp/1024/1024:.2f} MB)")

                initial_stream_receive_window = st.number_input("initial_stream_receive_window", value=st.session_state.quic_params_vals["init_stream"], help="QUIC初始流接收窗口大小")
                max_stream_receive_window = st.number_input("max_stream_receive_window", value=st.session_state.quic_params_vals["max_stream"], help="QUIC最大流接收窗口大小")
                initial_connection_receive_window = st.number_input("initial_connection_receive_window", value=st.session_state.quic_params_vals["init_conn"], help="QUIC初始连接接收窗口大小")
                max_connection_receive_window = st.number_input("max_connection_receive_window", value=st.session_state.quic_params_vals["max_conn"], help="QUIC最大连接接收窗口大小")
        
        hy2_hop_interval = st.number_input("跳跃间隔（单位：秒）", value=30, help="端口跳跃的时间间隔")
        hy2_fingerprint = st.selectbox("Fingerprint", ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "none"], index=0, help="TLS指纹，用于伪装客户端")
        hy2_ip_version = st.selectbox("IP Version", ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"], index=0, help="使用的IP协议版本，默认不设置")
    
    elif node_type == "tuic":
        col3, col4 = st.columns(2)
        with col3:
            tuic_uuid = st.text_input("UUID", "00000000-0000-4000-8000-000000000000", help="TUIC协议的用户UUID")
            tuic_password = st.text_input("Password", type="password", help="TUIC协议的密码")
            tuic_server_ip = st.text_input("Server IP", "1.2.3.4", help="服务器IP地址")
        with col4:
            tuic_congestion = st.selectbox("Congestion Controller", ["cubic", "new_reno", "bbr", "bbr2", "none"], index=0, help="拥塞控制算法")
            tuic_alpn = st.selectbox("ALPN", ["h3", "h3-29", "h3-27"], index=0, help="应用层协议协商标识")
            tuic_udp_relay_mode = st.selectbox("UDP Relay Mode", ["native", "quic"], index=0, help="UDP中继模式")
        
        # 将高级设置提出来
        tuic_heartbeat_interval = st.number_input("心跳间隔 (毫秒)", value=10000, help="Application Layer 心跳间隔")

        tuic_close_sni = st.checkbox("关闭 SNI 服务器名称指示", value=False, key=f"tuic_close_sni_{node_type}", help="是否关闭SNI服务器名称指示")
        tuic_reduce_rtt = st.checkbox("Reduce RTT", value=False, key=f"tuic_reduce_rtt_{node_type}", help="是否启用0-RTT握手")
        tuic_skip_cert_verify = st.checkbox("跳过证书验证", value=False, key=f"tuic_skip_cert_verify_{node_type}", help="是否跳过TLS证书验证")
        tuic_fast_open = st.checkbox("快速打开", value=True, key=f"tuic_fast_open_{node_type}", help="是否启用快速打开")
        tuic_ip_version = st.selectbox("IP Version", ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"], index=0, help="使用的IP协议版本，默认不设置")
    
    elif node_type == "vless":
        col3, col4 = st.columns(2)
        with col3:
            node_uuid = st.text_input("UUID", "your-uuid-here", help="VLESS协议的用户UUID")
            vless_tls = st.checkbox("TLS", value=True, key=f"vless_tls_{node_type}", help="是否启用TLS加密")
        with col4:
            vless_flow = st.selectbox("flow (reality)", ["none", "xtls-rprx-vision", "xtls-rprx-vision-udp443"], index=0, help="XTLS的流量特征")
            vless_servername = st.text_input("servername", "example.com", help="TLS握手时的服务器名称")
        
        vless_network = st.selectbox("传输协议", ["tcp", "kcp", "ws", "h2", "grpc", "http"], index=0, help="传输层协议")
        vless_packet_encoding = st.text_input("Packet-Encoding", "", help="数据包编码方式")
        # vless_udp 已统一使用上方的通用 UDP 选项
        vless_tfo = st.checkbox("TFO", value=False, key=f"vless_tfo_{node_type}", help="是否启用TCP Fast Open")
        vless_fp = st.selectbox("客户端指纹", ["chrome", "firefox", "safari", "edge", "ios", "android", "random", "none"], index=0, help="TLS客户端指纹")
        vless_ip_version = st.selectbox("IP Version", ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"], index=0, help="使用的IP协议版本，默认不设置")
        
        # Reality相关参数
        if vless_flow != "none":
            with st.expander("Reality 设置", expanded=True):
                vless_public_key = st.text_input("public-key (reality)", "", help="Reality协议的公钥")
                vless_short_id = st.text_input("short-id (reality)", "", help="Reality协议的短ID")
        else:
            vless_public_key = ""
            vless_short_id = ""
        
        # 其他选项
        vless_skip_cert_verify = st.checkbox("跳过证书验证", value=False, key=f"vless_skip_cert_verify_{node_type}", help="是否跳过TLS证书验证")
    
    elif node_type == "anytls":
        col3, col4 = st.columns(2)
        with col3:
            anytls_password = st.text_input("密码", type="password", help="AnyTLS协议的密码")
            anytls_sni = st.text_input("SNI", "example.com", help="TLS握手时的服务器名称指示")
            anytls_fp = st.selectbox("客户端指纹", ["chrome", "firefox", "safari", "edge", "ios", "android", "random", "none"], index=0, help="TLS客户端指纹")
        with col4:
            anytls_skip_cert_verify = st.checkbox("跳过证书验证", value=False, key=f"anytls_skip_cert_verify_{node_type}", help="是否跳过TLS证书验证")
            anytls_alpn = st.selectbox("ALPN", ["none", "h2", "http/1.1", "h2,http/1.1"], index=0, help="应用层协议协商标识")
            anytls_ip_version = st.selectbox("IP Version", ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"], index=0, help="使用的IP协议版本，默认不设置")
        
        anytls_idle_session_check_interval = st.number_input("idle-session-check-interval", value=30, help="空闲会话检查间隔（秒）")
        anytls_idle_session_timeout = st.number_input("idle-session-timeout", value=180, help="空闲会话超时时间（秒）")
        anytls_min_idle_session = st.number_input("min-idle-session", value=2, help="最小空闲会话数")
    
    # 链式代理（dialer-proxy）选项 - 智能下拉选择
    use_dialer_proxy = st.checkbox("使用链式代理 (dialer-proxy)", value=False, key=f"use_dialer_proxy_{node_type}", help="是否通过另一个代理连接此节点")
    dialer_proxy_name = ""
    if use_dialer_proxy:
        # 获取现有的节点名称列表
        existing_proxy_names = [p['name'] for p in st.session_state.proxies_data]
        if existing_proxy_names:
            dialer_proxy_name = st.selectbox("选择前置代理节点", existing_proxy_names, key=f"dialer_proxy_select_{node_type}", help="选择已添加的节点作为前置代理")
        else:
            st.warning("暂无可用节点，请先添加其他节点作为前置代理")
            dialer_proxy_name = st.text_input("链式代理节点名称 (手动输入)", placeholder="输入用于链式连接的节点名称", key=f"dialer_proxy_name_{node_type}")

    # 构建节点配置
    manual_node = {
        "name": node_name,
        "type": node_type,
        "server": node_server,
        "port": node_port
    }

    # 根据节点类型添加特定配置
    if node_type == "vmess":
        manual_node["uuid"] = node_uuid
        manual_node["alterId"] = node_alterid
        manual_node["cipher"] = vmess_encryption
        manual_node["tls"] = node_tls
        manual_node["skip-cert-verify"] = node_skip_cert
        manual_node["tfo"] = node_tfo
        manual_node["network"] = network_type
        if ip_version != "默认":
            manual_node["ip-version"] = ip_version
            
        if network_type == "ws":
            ws_opts = {"path": ws_path}
            if ws_host:
                ws_opts["headers"] = {"Host": ws_host}
            manual_node["ws-opts"] = ws_opts
        elif network_type == "h2":
            h2_opts = {"path": h2_path}
            if h2_host:
                h2_opts["host"] = [h2_host]
            manual_node["h2-opts"] = h2_opts
        elif network_type == "grpc":
            manual_node["grpc-service-name"] = grpc_service_name

    elif node_type == "ss":
        manual_node["password"] = node_password
        manual_node["cipher"] = ss_encryption
        manual_node["udp"] = node_udp
        manual_node["udp-over-tcp"] = ss_udp_over_tcp
        manual_node["tfo"] = ss_tfo
        manual_node["network"] = ss_network
        if ss_ip_version != "默认":
            manual_node["ip-version"] = ss_ip_version
        manual_node["mux"] = ss_mux

    elif node_type == "trojan":
        manual_node["password"] = node_password
        manual_node["udp"] = node_udp
        manual_node["udp-over-tcp"] = trojan_udp_over_tcp
        manual_node["tfo"] = trojan_tfo
        manual_node["network"] = trojan_network
        if trojan_ip_version != "默认":
            manual_node["ip-version"] = trojan_ip_version
        
        if trojan_network == "ws":
            ws_opts = {"path": ws_path}
            if ws_host:
                ws_opts["headers"] = {"Host": ws_host}
            manual_node["ws-opts"] = ws_opts
        elif trojan_network == "grpc":
            manual_node["grpc-opts"] = {"grpc-service-name": grpc_service_name}

    elif node_type == "hysteria2":
        manual_node["password"] = node_password
        manual_node["sni"] = hy2_sni
        manual_node["skip-cert-verify"] = hy2_skip_cert
        manual_node["alpn"] = [hy2_alpn]
        if hy2_obfs_type and hy2_obfs_type != "none":
            manual_node["obfs"] = {
                "type": hy2_obfs_type,
                "password": hy2_obfs_password
            }
        manual_node["up"] = f"{hy2_up_mbps} Mbps"
        manual_node["down"] = f"{hy2_down_mbps} Mbps"
        manual_node["hop-interval"] = hy2_hop_interval
        manual_node["fingerprint"] = hy2_fingerprint
        if hy2_ip_version != "默认":
            manual_node["ip-version"] = hy2_ip_version
            
        if enable_port_hopping:
            manual_node["ports"] = port_hopping_range
        if enable_protocol:
            manual_node["protocol"] = hy2_protocol
        if enable_quic_params:
            manual_node["quic-params"] = {
                "initial-stream-receive-window": initial_stream_receive_window,
                "max-stream-receive-window": max_stream_receive_window,
                "initial-connection-receive-window": initial_connection_receive_window,
                "max-connection-receive-window": max_connection_receive_window
            }

    elif node_type == "tuic":
        manual_node["uuid"] = tuic_uuid
        manual_node["password"] = tuic_password
        manual_node["ip"] = tuic_server_ip
        manual_node["congestion-controller"] = tuic_congestion
        manual_node["alpn"] = [tuic_alpn]
        manual_node["udp-relay-mode"] = tuic_udp_relay_mode
        manual_node["disable-sni"] = tuic_close_sni
        if not tuic_close_sni:
            manual_node["sni"] = node_server
        manual_node["reduce-rtt"] = tuic_reduce_rtt
        manual_node["skip-cert-verify"] = tuic_skip_cert_verify
        manual_node["fast-open"] = tuic_fast_open
        if tuic_ip_version != "默认":
            manual_node["ip-version"] = tuic_ip_version
        manual_node["heartbeat-interval"] = tuic_heartbeat_interval

    elif node_type == "vless":
        manual_node["uuid"] = node_uuid
        manual_node["tls"] = vless_tls
        manual_node["servername"] = vless_servername
        manual_node["network"] = vless_network
        # 修复逻辑: 只有当 flow 不为 none 时才添加该字段
        if vless_flow != "none":
            manual_node["flow"] = vless_flow
        
        if vless_packet_encoding:
             manual_node["packet-encoding"] = vless_packet_encoding
        manual_node["udp"] = node_udp
        manual_node["tfo"] = vless_tfo
        manual_node["client-fingerprint"] = vless_fp
        if vless_ip_version != "默认":
            manual_node["ip-version"] = vless_ip_version
        manual_node["skip-cert-verify"] = vless_skip_cert_verify
        
        # Reality / Utils
        if vless_public_key:
             manual_node["reality-opts"] = {"public-key": vless_public_key}
             if vless_short_id:
                 manual_node["reality-opts"]["short-id"] = vless_short_id
        
        # WS Opts etc.
        if vless_network == "ws":
            # 这是一个 UI 缺失，但我们至少先把已有的值填对。
             pass
        elif vless_network == "grpc":
             # 同上，缺少 input
             pass

    elif node_type == "anytls":
        manual_node["password"] = anytls_password
        manual_node["skip-cert-verify"] = anytls_skip_cert_verify
        manual_node["sni"] = anytls_sni
        if anytls_alpn != "none":
            manual_node["alpn"] = anytls_alpn.split(",") if "," in anytls_alpn else [anytls_alpn]
        manual_node["idle-session-check-interval"] = anytls_idle_session_check_interval
        manual_node["idle-session-timeout"] = anytls_idle_session_timeout
        manual_node["min-idle-session"] = anytls_min_idle_session
        manual_node["client-fingerprint"] = anytls_fp
        manual_node["udp"] = node_udp
        if anytls_ip_version != "默认":
            manual_node["ip-version"] = anytls_ip_version

    # 添加链式代理配置
    if use_dialer_proxy and dialer_proxy_name:
        manual_node["dialer-proxy"] = dialer_proxy_name

    st.json(manual_node)
    
    # 添加手动节点按钮
    if st.button("添加节点", key=f"add_manual_node_{node_type}", help="将当前配置的节点添加到列表"):
        # 检查是否已存在相同的节点
        if manual_node not in st.session_state.proxies_data:
            st.session_state.proxies_data.append(manual_node)
            st.success(f"节点 '{manual_node['name']}' 已添加！")
        else:
            st.warning(f"节点 '{manual_node['name']}' 已存在，跳过重复添加")

    # 节点管理功能
    st.subheader("节点管理")
    
    if not st.session_state.proxies_data:
        st.warning("请先添加一些节点以管理")
    else:
        # 显示所有节点并提供删除/修改功能
        for idx, proxy in enumerate(st.session_state.proxies_data):
            proxy_expander = st.expander(f"节点: {proxy['name']}", expanded=False)
            with proxy_expander:
                col_proxy_actions, col_proxy_type = st.columns([3, 1])
                with col_proxy_actions:
                    if st.button(f"删除节点 {proxy['name']}", key=f"delete_proxy_{idx}"):
                        st.session_state.proxies_data.pop(idx)
                        st.success(f"节点 {proxy['name']} 已删除")
                        st.rerun()
                with col_proxy_type:
                    st.caption(f"类型: {proxy['type']}")
                
                # 显示节点详细信息
                proxy_details = proxy.copy()
                st.json(proxy_details)
                
                # 修改节点功能
                if st.button(f"编辑节点 {proxy['name']}", key=f"edit_proxy_{idx}"):
                    # 将节点信息存储到session state，以便在其他地方使用
                    st.session_state.editing_proxy_idx = idx
                    st.session_state.editing_proxy_data = proxy.copy()
                    st.info(f"正在编辑节点 {proxy['name']}，请修改参数后点击'添加节点'按钮保存")
        
        st.markdown("---")
        
        # 检查是否有正在编辑的节点
        if 'editing_proxy_idx' in st.session_state and 'editing_proxy_data' in st.session_state:
            editing_idx = st.session_state.editing_proxy_idx
            editing_data = st.session_state.editing_proxy_data
            
            st.subheader("编辑节点")
            st.info(f"正在编辑节点: {editing_data['name']}")
            
            # 将节点数据转换为YAML格式
            yaml_data = yaml.dump([editing_data], default_flow_style=False, allow_unicode=True)
            
            # 允许用户编辑YAML格式的节点配置
            updated_yaml = st.text_area("编辑节点配置 (YAML格式)", value=yaml_data, height=300)
            
            if st.button("保存修改"):
                try:
                    # 解析YAML格式的节点配置
                    updated_data = yaml.safe_load(updated_yaml)
                    if isinstance(updated_data, list) and len(updated_data) > 0:
                        updated_proxy = updated_data[0]
                        
                        # 验证必要的字段
                        if 'name' in updated_proxy and 'type' in updated_proxy and 'server' in updated_proxy and 'port' in updated_proxy:
                            # 更新节点信息
                            st.session_state.proxies_data[editing_idx] = updated_proxy
                            
                            # 清除编辑状态
                            del st.session_state.editing_proxy_idx
                            del st.session_state.editing_proxy_data
                            
                            st.success("节点信息已更新")
                            st.rerun()
                        else:
                            st.error("YAML格式错误：节点配置缺少必要的字段 (name, type, server, port)")
                    else:
                        st.error("YAML格式错误：请确保输入的是有效的节点配置")
                except Exception as e:
                    st.error(f"YAML解析错误: {e}")

with tab3:
    st.header("分流规则配置")
    
    if not st.session_state.proxies_data:
        st.warning("请先在“快速填入”或“节点管理”标签页添加节点，才能配置分流规则。")
    else:
        # ==========================
        # 1. 准备配置上下文
        # ==========================
        try:
            proxy_groups = generate_proxy_groups(st.session_state.proxies_data)
        except Exception:
            proxy_groups = []

        # 构建基础预览配置
        preview_config = {
            "global": {
                "port": st.session_state.global_config["port"],
                "socks-port": st.session_state.global_config["socks_port"],
                "mixed-port": st.session_state.global_config["mixed_port"],
                "allow-lan": st.session_state.global_config["allow_lan"],
                "bind-address": st.session_state.global_config["bind_address"],
                "mode": st.session_state.global_config["mode"],
                "log-level": st.session_state.global_config["log_level"],
                "ipv6": st.session_state.global_config["ipv6_support"]
            },
            "proxies": st.session_state.proxies_data,
            "proxy-groups": proxy_groups,
            "rules": [
                "DOMAIN-SUFFIX,google.com,Proxy",
                "GEOIP,CN,Domestic",
                "MATCH,Others"
            ]
        }
        
        # 添加 TUN 设置
        if st.session_state.global_config["enable_tun"]:
            preview_config["tun"] = {
                "enable": True,
                "stack": st.session_state.global_config["tun_stack"],
                "device": st.session_state.global_config["tun_device"],
                "auto-route": st.session_state.global_config["tun_auto_route"],
                "auto-detect-interface": st.session_state.global_config["tun_auto_detect_interface"],
                "dns-hijack": ["any:53"] if st.session_state.global_config["tun_dns_hijack"] else []
            }
        
        # 添加 DNS 设置
        if st.session_state.global_config["enable_dns"]:
            def text_to_list(text):
                return [x.strip() for x in text.split('\n') if x.strip()]
                
            preview_config["dns"] = {
                "enable": True,
                "listen": st.session_state.global_config["dns_listen"],
                "ipv6": st.session_state.global_config["dns_ipv6"],
                "enhanced-mode": st.session_state.global_config["enhanced_mode"],
                "fake-ip-range": st.session_state.global_config["fake_ip_range"],
                "fake-ip-filter": ["*.lan", "*.local", "time.windows.com"] + FAKE_IP_FILTER_LIST,
                "default-nameserver": text_to_list(st.session_state.global_config["default_nameserver"]),
                "nameserver": text_to_list(st.session_state.global_config["nameserver"]),
                "fallback": text_to_list(st.session_state.global_config["fallback"]),
                "fallback-filter": {"geoip": True, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"]}
            }
            
            # 处理 Nameserver Policy
            if "nameserver_policy" in st.session_state.global_config and st.session_state.global_config["nameserver_policy"]:
                try:
                    policy_dict = {}
                    lines = st.session_state.global_config["nameserver_policy"].split('\n')
                    for line in lines:
                        if ':' in line:
                            # 简单处理：key: value
                            k, v = line.split(':', 1)
                            policy_dict[k.strip()] = v.strip()
                    if policy_dict:
                        preview_config["dns"]["nameserver-policy"] = policy_dict
                except:
                    pass
        
        if st.session_state.global_config["secret"]:
            preview_config["secret"] = st.session_state.global_config["secret"]
        
        # ==========================
        # 1. 规则集选择 (仅保留 lhie1)
        # ==========================
        # 默认选中 lhie1 且不展示下拉框 (或者展示但不可选)
        rule_type = "lhie1规则"
        st.session_state.selected_rule_type = rule_type
        st.info("💡 默认使用 lhie1 规则集进行基础分流。您可以在下方添加自定义规则或规则集。")

        # ==========================
        # 2. 可视化规则编辑 
        # ==========================
        st.subheader("可视化规则编辑")
        
        # 获取所有策略组名称用于下拉菜单
        all_groups = [group['name'] for group in proxy_groups]
        all_groups.extend(['DIRECT', 'REJECT', 'Proxy'])
        all_groups = list(set(all_groups))
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("**规则类型**")
            rule_select = st.selectbox("选择规则类型", 
                                     ["DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD", "IP-CIDR", "GEOIP", "MATCH"],
                                     key="rule_type_select_v3")
        with col2:
            st.write("**目标策略**")
            # 增加自定义组输入
            group_options = ["选择现有策略组...", "手动输入..."] + all_groups
            group_mode = st.selectbox("选择目标策略组模式", ["从列表中选择", "手动输入名称"], label_visibility="collapsed", key="group_mode_select")
            
            if group_mode == "从列表中选择":
                group_select = st.selectbox("选择目标策略组", all_groups, key="target_group_select_v3")
                final_group = group_select
            else:
                custom_group_input = st.text_input("输入策略组名称", placeholder="例如: MyGroup", key="custom_group_input_v3")
                final_group = custom_group_input

        rule_value = ""
        if rule_select not in ["MATCH"]:
            rule_value = st.text_input("输入值 (域名/IP/国家代码)", placeholder="例如: google.com", key="rule_value_input_v3")
        
        # 添加规则按钮
        if st.button("➕ 添加规则", key="add_rule_v3"):            
            if not final_group:
                 st.error("请选择或输入目标策略组")
            elif rule_select != "MATCH" and not rule_value:
                 st.error("请输入规则值")
            else:
                new_rule = f"{rule_select},{rule_value},{final_group}" if rule_select != "MATCH" else f"{final_group},{final_group}"
                if new_rule not in st.session_state.custom_rules:
                    st.session_state.custom_rules.append(new_rule)
                    st.success(f"规则已添加: {new_rule}")
                else:
                    st.warning("该规则已存在")
        
        # 自定义规则列表展示 (移至此处)
        if st.session_state.custom_rules:
            st.subheader(f"已添加的自定义规则 ({len(st.session_state.custom_rules)})")
            for i, rule in enumerate(st.session_state.custom_rules):
                col_rule, col_action = st.columns([4, 1])
                with col_rule:
                    st.text(f"{i+1}. {rule}")
                with col_action:
                    if st.button(f"🗑️", key=f"delete_custom_rule_{i}", help="删除此规则"):
                        st.session_state.custom_rules.pop(i)
                        st.rerun()
                        
        st.divider()

        # ==========================
        # 3. 编辑规则集配置 (Rule Providers)
        # ==========================
        st.subheader("编辑规则集配置 (Rule Providers)")
        st.caption("规则集使用介绍: https://wiki.metacubex.one/config/rule-providers/content/")
        
        with st.expander("➕ 添加新规则集", expanded=True):
            # 配置文件选项移除，默认全部
            rp_name = st.text_input("别名 (请勿重名)", placeholder="Rule-provider - " + str(uuid.uuid4())[:8], key="rp_name")
            
            col_rp1, col_rp2 = st.columns(2)
            with col_rp1:
                rp_type = st.selectbox("规则集类型", ["http", "file"], key="rp_type")
                rp_behavior = st.selectbox("规则类型", ["domain", "ipcidr", "classical"], key="rp_behavior")
            with col_rp2:
                rp_format = st.selectbox("规则格式", ["yaml", "text"], key="rp_format")
                rp_interval = st.number_input("规则集更新时间 (秒)", value=86400, key="rp_interval")
            
            rp_path_or_url = ""
            if rp_type == "http":
                rp_url = st.text_input("规则集地址", placeholder="http://...", key="rp_url")
                # 连通性测试按钮
                if rp_url:
                    if st.button("测试链接可用性", key="test_rp_url"):
                         try:
                             resp = requests.head(rp_url, timeout=5)
                             if resp.status_code == 200:
                                 st.success("✅ 链接可用")
                             else:
                                 st.warning(f"⚠️ 链接返回状态码: {resp.status_code}")
                         except Exception as e:
                             st.error(f"❌ 连接失败: {e}")
                
            elif rp_type == "file":
                uploaded_file = st.file_uploader("上传规则文件", type=["yaml", "yml", "txt", "list"], key="rp_file_upload")
                if uploaded_file:
                    # 保存文件逻辑
                    ruleset_dir = "ruleset"
                    if not os.path.exists(ruleset_dir):
                        os.makedirs(ruleset_dir)
                    # 使用别名或原文件名
                    safe_filename = f"{rp_name}.{rp_format}" if rp_name else uploaded_file.name
                    file_path = os.path.join(ruleset_dir, safe_filename)
                    with open(file_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    st.success(f"已保存到: {file_path}")
            
            rp_order = st.selectbox("规则集匹配顺序", ["优先 (覆盖)", "默认 (追加)"], key="rp_order")
            
            # 获取所有策略组名称用于下拉菜单
            rp_target = st.selectbox("指定策略组", list(set(all_groups)), key="rp_target")
            
            if st.button("保存规则集配置", key="save_rp"):
                if not rp_name:
                    st.error("请输入规则集别名")
                elif rp_name in st.session_state.custom_rule_providers:
                    st.error("该别名已存在")
                elif rp_type == "http" and not rp_url:
                    st.error("请输入规则集 URL")
                elif rp_type == "file" and not uploaded_file:
                     st.error("请上传规则文件")
                else:
                    provider_config = {
                        "type": rp_type,
                        "behavior": rp_behavior,
                        "interval": rp_interval,
                        "format": rp_format,
                        "target": rp_target,
                        "order": rp_order
                    }
                    
                    if rp_type == "http":
                        provider_config["url"] = rp_url
                        provider_config["path"] = f"./ruleset/{rp_name}.{rp_format}"
                    elif rp_type == "file":
                         provider_config["path"] = f"./ruleset/{safe_filename}" # 使用刚才保存的路径

                    st.session_state.custom_rule_providers[rp_name] = provider_config
                    st.success(f"规则集 {rp_name} 已添加")
        
        # 显示已添加的规则集
        if st.session_state.custom_rule_providers:
            st.write(f"**已添加的规则集列表 ({len(st.session_state.custom_rule_providers)})**")
            for name, config in list(st.session_state.custom_rule_providers.items()):
                target_group = config.get('target', '未指定')
                with st.expander(f"{name} ({target_group})"):
                    st.json(config)
                    if st.button(f"删除 {name}", key=f"del_rp_{name}"):
                        del st.session_state.custom_rule_providers[name]
                        st.rerun()

with tab4:
    st.header("配置生成与检查")
    
    # 上传旧配置 (仅当无节点时显示，方便修改)
    if not st.session_state.proxies_data:
        uploaded_yaml = st.file_uploader("📂 上传之前的配置文件 (进行修改)", type=["yaml", "yml"])
        if uploaded_yaml:
            if uploaded_yaml.size > 5 * 1024 * 1024:
                st.error("❌ 文件大小超过 5MB限制，请上传较小的配置文件")
            else:
                try:
                    content = uploaded_yaml.read().decode("utf-8")
                    # 检查标记 (简单的字符串检查)
                    if "# Generator: Clash-Config-Gen" in content or True: # 暂时放开 True 以便测试，实际应严格检查
                        data = yaml.safe_load(content)
                        if "proxies" in data:
                            st.session_state.proxies_data = data["proxies"]
                            st.success(f"已恢复 {len(data['proxies'])} 个节点！")
                            st.rerun()
                    else:
                        st.error("此文件不是由本工具生成的，或版本太旧，无法还原编辑。")
                except Exception as e:
                    st.error(f"解析失败: {e}")

    if st.button("🔍 生成并检查配置文件", type="primary", use_container_width=True):
        if not st.session_state.proxies_data:
            st.error("❌ 错误: 未添加任何节点！无法生成配置。")
        else:
            # 1. 重新构建配置 (复用逻辑)
            try:
                final_proxy_groups = generate_proxy_groups(st.session_state.proxies_data)
            except Exception as e:
                final_proxy_groups = []
                st.error(f"策略组生成失败: {e}")

            # 构建基础配置
            final_config = {
                "global": { # 兼容不同Clash版本的字段结构，这里我们混合输出，Clash Meta会自动识别一级key
                    "port": st.session_state.global_config["port"],
                    "socks-port": st.session_state.global_config["socks_port"],
                    "mixed-port": st.session_state.global_config["mixed_port"],
                    "allow-lan": st.session_state.global_config["allow_lan"],
                    "bind-address": st.session_state.global_config["bind_address"],
                    "mode": st.session_state.global_config["mode"],
                    "log-level": st.session_state.global_config["log_level"],
                    "ipv6": st.session_state.global_config["ipv6_support"],
                    "external-controller": st.session_state.global_config["external_controller"],
                    "find-process-mode": st.session_state.global_config["find_process_mode"]
                },
                # 直接展开到根节点
                "port": st.session_state.global_config["port"],
                "socks-port": st.session_state.global_config["socks_port"],
                "mixed-port": st.session_state.global_config["mixed_port"],
                "allow-lan": st.session_state.global_config["allow_lan"],
                "bind-address": st.session_state.global_config["bind_address"],
                "mode": st.session_state.global_config["mode"],
                "log-level": st.session_state.global_config["log_level"],
                "ipv6": st.session_state.global_config["ipv6_support"],
                "external-controller": st.session_state.global_config["external_controller"],
                "find-process-mode": st.session_state.global_config["find_process_mode"],
                
                "proxies": st.session_state.proxies_data,
                "proxy-groups": final_proxy_groups
            }
            
            # TUN
            if st.session_state.global_config["enable_tun"]:
                final_config["tun"] = {
                    "enable": True,
                    "stack": st.session_state.global_config["tun_stack"],
                    "device": st.session_state.global_config["tun_device"],
                    "auto-route": st.session_state.global_config["tun_auto_route"],
                    "auto-detect-interface": st.session_state.global_config["tun_auto_detect_interface"],
                    "dns-hijack": ["any:53"] if st.session_state.global_config["tun_dns_hijack"] else []
                }
            
            # DNS
            if st.session_state.global_config["enable_dns"]:
                 final_config["dns"] = {
                    "enable": True,
                    "listen": st.session_state.global_config["dns_listen"],
                    "ipv6": st.session_state.global_config["dns_ipv6"],
                    "enhanced-mode": st.session_state.global_config["enhanced_mode"],
                    "fake-ip-range": st.session_state.global_config["fake_ip_range"],
                    "fake-ip-filter": ["*.lan", "*.local", "time.windows.com"] + FAKE_IP_FILTER_LIST,
                    "default-nameserver": text_to_list(st.session_state.global_config["default_nameserver"]),
                    "nameserver": text_to_list(st.session_state.global_config["nameserver"]),
                    "fallback": text_to_list(st.session_state.global_config["fallback"]),
                    "fallback-filter": {"geoip": True, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"]}
                }
                 # Nameserver Policy
                 if "nameserver_policy" in st.session_state.global_config and st.session_state.global_config["nameserver_policy"]:
                    try:
                        policy_dict = {}
                        lines = st.session_state.global_config["nameserver_policy"].split('\n')
                        for line in lines:
                            if ':' in line:
                                k, v = line.split(':', 1)
                                policy_dict[k.strip()] = v.strip()
                        if policy_dict:
                            final_config["dns"]["nameserver-policy"] = policy_dict
                    except:
                        pass
            
            # Secret
            if st.session_state.global_config["secret"]:
                final_config["secret"] = st.session_state.global_config["secret"]
            
            # Meta Core Features
            final_config["tcp-concurrent"] = st.session_state.global_config["tcp_concurrent"]
            final_config["unified-delay"] = st.session_state.global_config["unified_delay"]
            final_config["geodata-mode"] = st.session_state.global_config["geodata_mode"]
            final_config["geodata-loader"] = st.session_state.global_config["geodata_loader"]
            if st.session_state.global_config["enable_sniffer"]:
                final_config["sniffer"] = {
                    "enable": True,
                    "sniff": {
                        "TLS": {"ports": [443]},
                        "HTTP": {"ports": [80], "override-destination": True}
                    },
                    "force-domain": SNIFFER_FORCE_DOMAIN,
                    "skip-domain": SNIFFER_SKIP_DOMAIN
                }

            # 处理规则 (Rules)
            selected_rule = st.session_state.get("selected_rule_type", "自定义规则")
            rule_list = []
            
            # 为了简化逻辑，这里重复部分规则生成逻辑，实际项目中应封装函数
            if selected_rule == "lhie1规则":
                # 按照 config.yaml 的 dler-io 规则集重构 (用户习惯称之为 lhie1)
                final_config["rule-providers"] = {}
                base_url = "https://testingcf.jsdelivr.net/gh/dler-io/Rules@main/Clash/Provider"
                
                # 定义规则集与Target策略组的映射关系
                # Key: Provider Name (也是文件名的一部分)
                # Value: (Path Suffix, Target Group)
                # Path Suffix 如果为 None，则默认与 Key 相同
                
                providers_map = {
                    "AdBlock": ("AdBlock", "AdBlock"),
                    "HTTPDNS": ("HTTPDNS", "HTTPDNS"),
                    "Special": ("Special", "DIRECT"),
                    "PROXY": ("Proxy", "Proxy"),
                    "Domestic": ("Domestic", "Domestic"),
                    "Domestic IPs": ("Domestic%20IPs", "Domestic"),
                    "LAN": ("LAN", "DIRECT"),
                    "Netflix": ("Media/Netflix", "Netflix"),
                    "Spotify": ("Media/Spotify", "Spotify"),
                    "YouTube": ("Media/YouTube", "Youtube"), # 注意 Group 是 Youtube
                    "Max": ("Media/Max", "HBO Max"),
                    "Bilibili": ("Media/Bilibili", "Bilibili"),
                    "IQ": ("Media/IQ", "Asian TV"),
                    "IQIYI": ("Media/IQIYI", "Asian TV"),
                    "Letv": ("Media/Letv", "Asian TV"),
                    "Netease Music": ("Media/Netease%20Music", "Asian TV"),
                    "Tencent Video": ("Media/Tencent%20Video", "Asian TV"),
                    "Youku": ("Media/Youku", "Asian TV"),
                    "WeTV": ("Media/WeTV", "Global TV"),
                    "ABC": ("Media/ABC", "Global TV"),
                    "Abema TV": ("Media/Abema%20TV", "Asian TV"),
                    "Amazon": ("Media/Amazon", "Global TV"),
                    "Apple Music": ("Media/Apple%20Music", "Apple"),
                    "Apple News": ("Media/Apple%20News", "Apple"),
                    "Apple TV": ("Media/Apple%20TV", "Apple TV"),
                    "Bahamut": ("Media/Bahamut", "Bahamut"),
                    "BBC iPlayer": ("Media/BBC%20iPlayer", "Global TV"),
                    "DAZN": ("Media/DAZN", "DAZN"),
                    "Discovery Plus": ("Media/Discovery%20Plus", "Discovery Plus"),
                    "Disney Plus": ("Media/Disney%20Plus", "Disney Plus"),
                    "DMM": ("Media/DMM", "Asian TV"),
                    "encoreTVB": ("Media/encoreTVB", "Global TV"),
                    "F1 TV": ("Media/F1%20TV", "Global TV"),
                    "Fox Now": ("Media/Fox%20Now", "Global TV"),
                    "Fox+": ("Media/Fox%2B", "Asian TV"),
                    "Hulu Japan": ("Media/Hulu%20Japan", "Asian TV"),
                    "Hulu": ("Media/Hulu", "Global TV"),
                    "Japonx": ("Media/Japonx", "Asian TV"),
                    "JOOX": ("Media/JOOX", "Asian TV"),
                    "KKBOX": ("Media/KKBOX", "Asian TV"),
                    "KKTV": ("Media/KKTV", "Asian TV"),
                    "Line TV": ("Media/Line%20TV", "Asian TV"),
                    "myTV SUPER": ("Media/myTV%20SUPER", "Asian TV"),
                    "Niconico": ("Media/Niconico", "Asian TV"),
                    "Pandora": ("Media/Pandora", "Global TV"),
                    "PBS": ("Media/PBS", "Global TV"),
                    "Pornhub": ("Media/Pornhub", "Pornhub"),
                    "Soundcloud": ("Media/Soundcloud", "Global TV"),
                    "ViuTV": ("Media/ViuTV", "Asian TV"),
                    "Telegram": ("Telegram", "Telegram"),
                    "Crypto": ("Crypto", "Crypto"),
                    "Discord": ("Discord", "Discord"),
                    "Steam": ("Steam", "Steam"),
                    "TikTok": ("TikTok", "TikTok"),
                    "Speedtest": ("Speedtest", "Speedtest"),
                    "PayPal": ("PayPal", "PayPal"),
                    "Microsoft": ("Microsoft", "Microsoft"),
                    "AI Suite": ("AI%20Suite", "AI Suite"),
                    "Apple": ("Apple", "Apple"),
                    "Google FCM": ("Google%20FCM", "Google FCM"),
                    "Scholar": ("Scholar", "Scholar"),
                    "miHoYo": (None, "miHoYo") # URL in root
                }
                
                rule_list = []
                
                for name, (suffix, target) in providers_map.items():
                    # 1. Add Provider
                    real_suffix = suffix if suffix else name
                    final_config["rule-providers"][name] = {
                        "type": "http",
                        "behavior": "classical",
                        "url": f"{base_url}/{real_suffix}.yaml",
                        "path": f"./ruleset/{name.replace(' ', '_')}.yaml",
                        "interval": 86400
                    }
                    # 2. Add Rule
                    rule_list.append(f"RULE-SET,{name},{target}")

                # 添加 Google 特殊域名代理 (防止 DNS 泄露)
                rule_list = [
                    "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
                    "DOMAIN-SUFFIX,services.googleapis.cn,Proxy"
                ] + rule_list

                # 添加通用规则
                rule_list.extend([
                    "GEOIP,CN,Domestic,no-resolve",
                    "MATCH,Others"
                ])
            elif selected_rule == "自定义规则":
                rule_list = [
                    "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
                    "DOMAIN-SUFFIX,services.googleapis.cn,Proxy",
                    "DOMAIN-SUFFIX,google.com,Proxy", 
                    "DOMAIN-SUFFIX,youtube.com,Proxy", 
                    "GEOIP,CN,DIRECT,no-resolve", 
                    "MATCH,Proxy"
                ]
            else:
                rule_list = [
                    "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
                    "DOMAIN-SUFFIX,services.googleapis.cn,Proxy",
                    "GEOIP,CN,DIRECT,no-resolve", 
                    "MATCH,Proxy"
                ]
                
            # 处理自定义规则集 (Rule Providers)
            provider_rules_prepend = []
            provider_rules_append = []
            
            if "custom_rule_providers" in st.session_state and st.session_state.custom_rule_providers:
                if "rule-providers" not in final_config:
                    final_config["rule-providers"] = {}
                
                for name, config in st.session_state.custom_rule_providers.items():
                    # 添加到 rule-providers
                    provider = {
                        "type": config["type"],
                        "behavior": config["behavior"],
                        "path": config["path"],
                        "interval": config["interval"]
                    }
                    if config["type"] == "http":
                        provider["url"] = config["url"]
                    elif config["type"] == "file":
                        # 对于 file 类型，这里简单处理，实际可能需要处理文件路径
                         pass 
                         
                    if config["format"]:
                         provider["format"] = config["format"]

                    final_config["rule-providers"][name] = provider
                    
                    # 生成对应的规则
                    target_group = config.get('target', 'Proxy')
                    new_rule = f"RULE-SET,{name},{target_group}"
                    if config.get("order") == "优先 (覆盖)":
                        provider_rules_prepend.append(new_rule)
                    else:
                        provider_rules_append.append(new_rule)
            
            # 合并所有规则: 
            # 顺序: 自定义规则(单条) -> 优先覆盖的规则集 -> 选定的预设规则集(lhie1) -> 追加的规则集 -> 兜底
            # 注意：实际顺序取决于用户的预期，这里假设单条自定义规则优先级最高
            
            # 修正 lhie1 的 MATCH,Proxy，避免被中间插入的规则截断（如果有 MATCH）
            # 通常预设规则最后一条是 MATCH，所以追加的规则可能无法生效。
            # 如果是 lhie1，它最后是 MATCH,Proxy。
            
            # 策略调整：
            # 1. 自定义单条规则 (最优先)
            # 2. 规则集 (优先覆盖)
            # 3. 预设规则 (lhie1) [除了最后的 MATCH]
            # 4. 规则集 (默认追加)
            # 5. 兜底 MATCH (如果预设里有)
            
            def split_rules(rules):
                """分离普通规则和兜底规则(MATCH)"""
                normal = []
                match = []
                for r in rules:
                    if r.startswith("MATCH,"):
                        match.append(r)
                    else:
                        normal.append(r)
                return normal, match

            preset_normal, preset_match = split_rules(rule_list)
            
            final_rules = []
            final_rules.extend(st.session_state.custom_rules)
            final_rules.extend(provider_rules_prepend)
            final_rules.extend(preset_normal)
            final_rules.extend(provider_rules_append)
            final_rules.extend(preset_match)
            
            # 如果没有兜底，添加默认兜底
            if not any(r.startswith("MATCH,") for r in final_rules):
                final_rules.append("MATCH,Proxy")

            final_config["rules"] = final_rules

            # --------------------------
            # 执行检查逻辑
            # --------------------------
            check_errors = []
            check_warnings = []
            
            # 1. 节点检查
            if not final_config["proxies"]:
                check_errors.append("Proxies 为空")
            
            # 2. 策略组检查
            all_proxy_names = [p['name'] for p in final_config["proxies"]]
            all_group_names = [g['name'] for g in final_config["proxy-groups"]]
            all_valid_targets = all_proxy_names + all_group_names + ["DIRECT", "REJECT", "no-resolve"]
            
            for group in final_config["proxy-groups"]:
                for p in group["proxies"]:
                    if p not in all_valid_targets:
                        check_warnings.append(f"策略组 '{group['name']}' 引用了不存在的节点/组: '{p}' (可能是正则筛选或其他)")
                        
            # 3. 规则检查 (简单检查)
            for r in final_config["rules"]:
                parts = r.split(',')
                if len(parts) >= 2:
                    target = parts[-1]
                    if target not in all_valid_targets:
                       check_warnings.append(f"规则 '{r}' 指向了不存在的策略组: '{target}'")

            # 显示结果
            if check_errors:
                st.error(f"❌ 检查发现 {len(check_errors)} 个错误:")
                for e in check_errors:
                    st.text(f"- {e}")
            else:
                st.success("✅ 基础配置检查通过！")
                
            if check_warnings:
                with st.expander(f"⚠️ 发现 {len(check_warnings)} 个潜在警告 (点击查看)", expanded=False):
                    for w in check_warnings:
                        st.warning(w)

            # 生成 YAML
            final_config_str = build_subscription_yaml(final_config)
            if not check_errors:
                save_user_config(
                    current_user["id"],
                    st.session_state.proxies_data,
                    st.session_state.global_config,
                    st.session_state.custom_rules,
                    st.session_state.custom_rule_providers,
                    selected_rule,
                    final_config_str,
                )
                refreshed_config = get_user_config(current_user["id"])
                st.success(f"订阅已保存并立即生效: {get_public_base_url()}/sub/{refreshed_config['token']}")
            
            st.divider()
            col_d1, col_d2 = st.columns([3, 1])
            with col_d1:
                st.text_area("配置预览 (全文)", value=final_config_str, height=600)
            with col_d2:
                st.download_button(
                    label="📥 下载 config.yaml",
                    data=final_config_str,
                    file_name="config.yaml",
                    mime="application/x-yaml",
                    type="primary",
                    use_container_width=True,
                    help="下载最终生成的配置文件"
                )
