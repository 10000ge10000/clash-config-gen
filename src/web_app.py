import html
import streamlit as st
import streamlit.components.v1 as components
import yaml
import requests
import json
import uuid
import ipaddress
import re
import socket
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlparse

from auth import get_bool_env
from config_defaults import build_default_global_config
from config_builder import (
    DEFAULT_RULE_TYPE,
    DUSTINWIN_PROVIDERS_MAP,
    LHIE1_PROVIDERS_MAP,
    build_config as build_subscription_config,
    build_yaml as build_subscription_yaml,
    validate_config as validate_subscription_config,
)
from importers import normalize_subscription_content, parse_proxy_yaml, parse_share_link
from mihomo_validator import validate_with_mihomo
from security import create_csrf_token
from storage import (
    delete_regular_user,
    ensure_admin_from_env,
    get_public_base_url,
    get_user_by_auth_session,
    get_user_config,
    init_db,
    list_users,
    reset_subscription_token,
    save_user_config,
    save_user_draft,
    set_user_enabled,
)
from ui.auth_view import render_auth_gate
from ui.node_view import render_node_management
from ui.publish_view import PUBLISH_DIFF_LABELS, render_publish_summary
from ui.rule_view import collect_rule_targets, render_rule_provider_list, render_single_rule_editor

MAX_REMOTE_SUBSCRIPTION_BYTES = 5 * 1024 * 1024
SAFE_RULESET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
PROJECT_REPOSITORY_URL = "https://github.com/10000ge10000/clash-config-gen"
MIHOMO_DOCUMENTATION_URL = "https://wiki.metacubex.one/"


def validate_external_url(url: str) -> str:
    """限制服务端主动访问目标，避免公开注册场景下被用来探测内网。"""
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("只支持 http/https URL")

    host = parsed.hostname
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise ValueError(f"无法解析 URL 主机: {host}") from exc

    for address in addresses:
        ip = ipaddress.ip_address(address)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError("URL 解析到内网、本机或保留地址，已拒绝服务端访问")
    return parsed.geturl()


def fetch_text_from_external_url(url: str, timeout: int = 15) -> tuple[str, str]:
    safe_url = validate_external_url(url)
    response = requests.get(safe_url, timeout=timeout, stream=True, allow_redirects=False)
    if 300 <= response.status_code < 400:
        response.close()
        raise ValueError("远程 URL 返回重定向，出于安全原因已拒绝")
    response.raise_for_status()
    content_type = response.headers.get("content-type", "")
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_REMOTE_SUBSCRIPTION_BYTES:
            raise ValueError("远程订阅内容超过 5MB，已停止下载")
        chunks.append(chunk)
    response.close()
    return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace"), content_type


def validate_ruleset_alias(name: str) -> str:
    alias = (name or "").strip()
    if not SAFE_RULESET_NAME_PATTERN.fullmatch(alias):
        raise ValueError("规则集别名只能使用 1-64 位字母、数字、点、下划线或短横线")
    return alias


def safe_ruleset_file_path(alias: str, rule_format: str, ruleset_dir: str = "ruleset") -> Path:
    safe_alias = validate_ruleset_alias(alias)
    safe_format = validate_ruleset_alias(rule_format)
    base_dir = Path(ruleset_dir).resolve()
    target_path = (base_dir / f"{safe_alias}.{safe_format}").resolve()
    if base_dir != target_path.parent:
        raise ValueError("规则集文件路径越界")
    return target_path

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

ASSETS_DIR = Path(__file__).with_name("assets")
BRAND_MARK_SVG = (ASSETS_DIR / "brand-mark.svg").read_text(encoding="utf-8")

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
    
    :root {
        color-scheme: dark;
    }
    .stApp {
        background: #050b14;
        color: #effcff;
    }
    [data-testid="stHeader"] {
        background: transparent;
    }
    /* 移除顶部默认的 padding */
    .block-container {
        max-width: 1280px;
        padding-top: 1.8rem !important;
        padding-bottom: 5rem !important;
    }
    [data-testid="stSidebar"] {
        background: #06101c;
        border-right: 1px solid #193349;
    }
    [data-testid="stSidebar"] * {
        color: #dcebf2;
    }
    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.15rem;
    }
    [data-testid="stSidebar"] .stHeadingContainer h1,
    [data-testid="stSidebar"] .stHeadingContainer h2,
    [data-testid="stSidebar"] .stHeadingContainer h3 {
        margin: .25rem 0 .45rem;
        font-size: 1.12rem;
        line-height: 1.35;
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] .stCaptionContainer {
        font-size: .78rem;
        line-height: 1.45;
    }
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
        gap: .55rem;
    }
    [data-testid="stSidebar"] hr {
        margin: .8rem 0;
        border-color: #152b3d;
    }
    [data-testid="stSidebar"] details {
        border-color: #21425b;
        border-radius: 6px;
        background: #081321;
    }
    [data-testid="stSidebar"] details summary {
        min-height: 38px;
        padding: .45rem .65rem;
        font-size: .78rem;
    }
    [data-testid="stSidebar"] [data-baseweb="input"] {
        min-height: 38px;
        border-color: #28506d;
        background: #f8fafc;
    }
    [data-testid="stSidebar"] [data-baseweb="input"] input {
        color: #172536 !important;
        background: #f8fafc !important;
        font-size: .78rem;
    }
    [data-testid="stSidebar"] [data-baseweb="radio"] {
        margin-bottom: .1rem;
    }
    [data-testid="stSidebar"] [data-testid="stAlertContainer"] {
        padding: .65rem .75rem;
        border-radius: 6px;
    }
    .stButton > button,
    .stDownloadButton > button,
    [data-testid="stFormSubmitButton"] > button {
        min-height: 38px;
        border: 1px solid #2b4b63 !important;
        border-radius: 6px !important;
        color: #effcff !important;
        background: #172333 !important;
        font-weight: 700 !important;
    }
    .stButton > button:hover,
    .stDownloadButton > button:hover,
    [data-testid="stFormSubmitButton"] > button:hover {
        border-color: #45ff7b !important;
        color: #45ff7b !important;
        background: #0b1928 !important;
    }
    .stButton > button[kind="primary"],
    [data-testid="stFormSubmitButton"] > button[kind="primary"] {
        border-color: #45ff7b !important;
        color: #03101e !important;
        background: #45ff7b !important;
    }
    .stButton > button:disabled,
    .stDownloadButton > button:disabled,
    [data-testid="stFormSubmitButton"] > button:disabled {
        border-color: #243647 !important;
        color: #748696 !important;
        background: #111b29 !important;
        opacity: 1 !important;
    }
    [data-baseweb="input"],
    [data-baseweb="textarea"],
    [data-baseweb="select"] > div {
        border-color: #28506d !important;
    }
    [data-baseweb="input"] input,
    [data-baseweb="textarea"] textarea {
        color: #172536 !important;
        background: #f8fafc !important;
        -webkit-text-fill-color: #172536 !important;
    }
    [data-testid="collapsedControl"],
    [data-testid="stSidebarCollapsedControl"] {
        display: flex !important;
        visibility: visible !important;
        opacity: 1 !important;
        pointer-events: auto !important;
        position: fixed !important;
        top: .85rem !important;
        left: .85rem !important;
        z-index: 999999 !important;
        background: #ffffff !important;
        border: 1px solid #e5e7eb !important;
        border-radius: 10px !important;
        box-shadow: 0 8px 22px rgba(15, 23, 42, .12) !important;
    }
    .auth-spacer {
        height: clamp(1.5rem, 9vh, 6rem);
    }
    .auth-page {
        position: fixed;
        inset: 0;
        z-index: 999998;
        overflow: auto;
        color: #effcff;
        background:
            linear-gradient(90deg, rgba(3, 12, 27, .22) 0%, rgba(3, 12, 27, .42) 50%, rgba(3, 12, 27, .96) 100%),
            url("/sub/assets/auth-future-city.png") center / cover fixed;
    }
    .auth-page::before {
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        background-image:
            linear-gradient(rgba(57, 255, 116, .045) 1px, transparent 1px),
            linear-gradient(90deg, rgba(57, 255, 116, .045) 1px, transparent 1px);
        background-size: 72px 72px;
        mask-image: linear-gradient(to bottom, rgba(0,0,0,.7), transparent 82%);
    }
    .auth-page::after {
        content: "";
        position: fixed;
        width: 7px;
        height: 7px;
        left: 18%;
        top: 72%;
        border-radius: 50%;
        background: #45ff7b;
        box-shadow:
            13vw -9vh 0 #45ff7b,
            31vw -3vh 0 #2bc9ff,
            43vw -20vh 0 #45ff7b,
            57vw -11vh 0 #45ff7b;
        filter: drop-shadow(0 0 10px rgba(69,255,123,.9));
        animation: auth-particles 5s ease-in-out infinite alternate;
        pointer-events: none;
    }
    .auth-layout {
        position: relative;
        z-index: 1;
        width: min(1320px, calc(100% - 64px));
        min-height: 100vh;
        margin: 0 auto;
        display: grid;
        grid-template-columns: minmax(0, 1fr) 428px;
        align-items: center;
        gap: 72px;
        padding: 48px 0;
    }
    .auth-brand {
        position: absolute;
        top: 48px;
        left: 0;
        display: flex;
        align-items: center;
        gap: 14px;
    }
    .auth-brand-mark {
        display: grid;
        place-items: center;
        width: 40px;
        height: 40px;
        border-radius: 6px;
        color: #03101e;
        background: #45ff7b;
        font-weight: 900;
        font-size: 1.15rem;
        box-shadow: 0 0 28px rgba(69,255,123,.25);
    }
    .auth-brand-name {
        font-size: 1.05rem;
        line-height: 1.2;
        font-weight: 800;
    }
    .auth-brand-desc {
        margin-top: 3px;
        color: #8fa7b9;
        font-size: .72rem;
    }
    .auth-intro {
        max-width: 670px;
        padding-top: 64px;
        animation: auth-enter .5s ease-out both;
    }
    .auth-eyebrow {
        margin-bottom: 22px;
        color: #45ff7b;
        font-size: .78rem;
        font-weight: 800;
    }
    .auth-intro h1 {
        margin: 0;
        color: #f0fbff;
        font-size: clamp(2.55rem, 4.4vw, 4rem);
        line-height: 1.17;
        letter-spacing: 0;
    }
    .auth-intro > p {
        max-width: 610px;
        margin: 26px 0 30px;
        color: #a1b5c5;
        font-size: 1.06rem;
        line-height: 1.75;
    }
    .auth-capabilities {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
    }
    .auth-capability {
        padding: 9px 13px;
        border: 1px solid rgba(69,255,123,.25);
        border-radius: 6px;
        color: #d8e9ef;
        background: rgba(4, 23, 40, .64);
        font-size: .82rem;
        backdrop-filter: blur(10px);
    }
    .auth-capability::before {
        content: "";
        display: inline-block;
        width: 7px;
        height: 7px;
        margin-right: 8px;
        border-radius: 50%;
        background: #45ff7b;
        box-shadow: 0 0 9px rgba(69,255,123,.8);
    }
    .auth-card {
        padding: 34px 32px 30px;
        border: 1px solid rgba(72, 132, 165, .6);
        border-radius: 8px;
        background: rgba(3, 14, 29, .94);
        box-shadow: 0 26px 70px rgba(0,0,0,.42);
        backdrop-filter: blur(18px);
        animation: auth-card-enter .42s ease-out both;
    }
    .auth-card h2 {
        margin: 0;
        color: #f0fbff;
        font-size: 1.7rem;
        letter-spacing: 0;
    }
    .auth-card-subtitle {
        margin: 7px 0 24px;
        color: #849cad;
        font-size: .9rem;
    }
    .auth-tabs {
        display: grid;
        grid-template-columns: 1fr 1fr;
        margin-bottom: 26px;
    }
    .auth-tab {
        padding: 13px 8px;
        border-bottom: 2px solid transparent;
        color: #879eae !important;
        text-align: center;
        text-decoration: none !important;
        font-weight: 700;
    }
    .auth-tab.active {
        border-color: #45ff7b;
        color: #45ff7b !important;
        background: rgba(18, 52, 74, .22);
    }
    .auth-form {
        display: grid;
        gap: 18px;
    }
    .auth-field {
        display: grid;
        gap: 8px;
        color: #9db0be;
        font-size: .82rem;
    }
    .auth-field input {
        box-sizing: border-box;
        width: 100%;
        height: 49px;
        padding: 0 15px;
        border: 1px solid #264a61;
        border-radius: 6px;
        outline: 0;
        color: #ecfaff;
        background: rgba(2, 12, 25, .75);
        font: inherit;
        font-size: .95rem;
        transition: border-color .18s, box-shadow .18s;
    }
    .auth-field input:focus {
        border-color: #45ff7b;
        box-shadow: 0 0 0 3px rgba(69,255,123,.12);
    }
    .auth-options {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        color: #91a7b7;
        font-size: .82rem;
    }
    .auth-remember {
        display: inline-flex;
        align-items: center;
        gap: 9px;
    }
    .auth-remember input {
        width: 17px;
        height: 17px;
        accent-color: #45ff7b;
    }
    .auth-submit {
        height: 50px;
        border: 0;
        border-radius: 6px;
        color: #03101e;
        background: #45ff7b;
        font-size: .96rem;
        font-weight: 850;
        cursor: pointer;
        transition: transform .18s, box-shadow .18s, background .18s;
    }
    .auth-submit:hover {
        transform: translateY(-1px);
        background: #65ff91;
        box-shadow: 0 12px 30px rgba(69,255,123,.18);
    }
    .auth-error {
        margin: 0 0 18px;
        padding: 11px 12px;
        border-left: 3px solid #ff5964;
        border-radius: 4px;
        color: #ffd5d8;
        background: rgba(110, 17, 31, .34);
        font-size: .82rem;
        line-height: 1.5;
    }
    .auth-security {
        margin-top: 24px;
        padding-top: 19px;
        border-top: 1px solid #173449;
        color: #8fa5b5;
        font-size: .76rem;
        text-align: center;
    }
    .auth-security::before {
        content: "";
        display: inline-block;
        width: 7px;
        height: 7px;
        margin-right: 8px;
        border-radius: 50%;
        background: #45ff7b;
    }
    .auth-registration-closed {
        padding: 13px;
        border: 1px solid #264a61;
        border-radius: 6px;
        color: #9fb3c1;
        background: rgba(13, 37, 55, .55);
        font-size: .84rem;
        line-height: 1.55;
    }
    .auth-product-note {
        position: absolute;
        left: 0;
        bottom: 48px;
        color: #9bb0be;
        font-size: .8rem;
    }
    form.auth-logout-form {
        margin: 0;
    }
    form.auth-logout-form button {
        width: 100%;
        padding: .55rem .75rem;
        border: 1px solid #d1d5db;
        border-radius: 6px;
        color: #374151;
        background: white;
        cursor: pointer;
        font-weight: 650;
    }
    @keyframes auth-enter {
        from { opacity: 0; transform: translateY(12px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes auth-card-enter {
        from { opacity: 0; transform: translateY(16px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes auth-particles {
        from { transform: translate3d(-8px, 5px, 0); opacity: .6; }
        to { transform: translate3d(10px, -9px, 0); opacity: 1; }
    }
    @media (prefers-reduced-motion: reduce) {
        .auth-page::after, .auth-intro, .auth-card { animation: none; }
    }
    @media (max-width: 820px) {
        .auth-layout {
            width: min(100% - 40px, 430px);
            grid-template-columns: 1fr;
            align-content: start;
            gap: 28px;
            padding: 28px 0 34px;
        }
        .auth-brand {
            position: static;
        }
        .auth-intro {
            padding-top: 20px;
        }
        .auth-intro h1 {
            font-size: 2.25rem;
        }
        .auth-intro > p {
            margin: 14px 0 0;
            font-size: .92rem;
        }
        .auth-capabilities, .auth-product-note {
            display: none;
        }
        .auth-card {
            padding: 28px 24px 26px;
        }
    }
    .auth-panel-title {
        margin: 0 0 .35rem 0;
        font-size: 1.6rem;
        line-height: 1.4;
        font-weight: 800;
        color: #1f2937;
        text-align: center;
    }
    .auth-panel-desc {
        margin: 0 0 1rem 0;
        color: #6b7280;
        text-align: center;
        line-height: 1.6;
    }
    div[data-baseweb="tab-list"] {
        gap: .9rem;
        border-bottom: 1px solid #21425b;
    }
    button[data-baseweb="tab"] {
        padding: .9rem .25rem .95rem !important;
        min-width: auto;
    }
    button[data-baseweb="tab"] p {
        font-size: 1.14rem;
        line-height: 1.45;
        font-weight: 750;
        color: #8fa7b9;
        letter-spacing: 0;
    }
    button[data-baseweb="tab"][aria-selected="true"] p {
        color: #45ff7b;
    }
    .workflow-step {
        display: flex;
        align-items: flex-start;
        gap: .75rem;
        padding: .85rem 1rem;
        margin: .35rem 0 1rem;
        border: 1px solid #21425b;
        border-radius: 8px;
        background: #081321;
        color: #effcff;
    }
    .workflow-step-number {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: 0 0 1.8rem;
        width: 1.8rem;
        height: 1.8rem;
        border-radius: 50%;
        background: #45ff7b;
        color: #03101e;
        font-weight: 800;
        font-size: .95rem;
    }
    .workflow-step-title {
        margin: 0 0 .1rem;
        font-size: 1.08rem;
        line-height: 1.45;
        font-weight: 800;
        color: #effcff;
    }
    .workflow-step-desc {
        margin: 0;
        font-size: .98rem;
        line-height: 1.6;
        color: #8fa7b9;
    }
    @media (max-width: 760px) {
        .block-container {
            padding: 1rem 1rem 5.5rem !important;
        }
        [data-testid="stSidebar"] { width: min(88vw, 340px) !important; }
    }

    /* 浅色主题覆盖：保留绿色操作强调色，统一应用页与登录页对比度。 */
    :root {
        color-scheme: light;
    }
    .stApp {
        color: #172536;
        background: #f4f7fb;
    }
    .stApp,
    .stApp p,
    .stApp label,
    .stApp h1,
    .stApp h2,
    .stApp h3,
    .stApp h4,
    .stApp h5,
    .stApp h6 {
        color: #172536;
    }
    [data-testid="stHeader"] {
        background: rgba(244, 247, 251, .92);
    }
    [data-testid="stSidebar"] {
        background: #ffffff;
        border-right-color: #d8e2ec;
    }
    [data-testid="stSidebar"] *,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] label {
        color: #233548;
    }
    [data-testid="stSidebar"] hr {
        border-color: #e2e8f0;
    }
    [data-testid="stSidebar"] details,
    [data-testid="stExpander"] details {
        border-color: #d8e2ec;
        background: #f8fafc;
    }
    [data-testid="stSidebar"] [data-testid="stAlertContainer"],
    [data-testid="stAlertContainer"] {
        border-color: #cfe0ee;
        background: #eef6ff;
    }
    div[data-baseweb="tab-list"] {
        border-bottom-color: #d8e2ec;
    }
    button[data-baseweb="tab"] p {
        color: #60758a;
    }
    button[data-baseweb="tab"][aria-selected="true"] p {
        color: #087a3e;
    }
    [data-baseweb="input"],
    [data-baseweb="textarea"],
    [data-baseweb="select"] > div,
    [data-baseweb="base-input"],
    [data-testid="stNumberInput"] > div > div {
        border-color: #c8d4df !important;
        background: #ffffff !important;
    }
    [data-baseweb="input"] input,
    [data-baseweb="textarea"] textarea,
    [data-baseweb="select"] input,
    [data-baseweb="select"] span {
        color: #172536 !important;
        background: #ffffff !important;
        -webkit-text-fill-color: #172536 !important;
    }
    [data-baseweb="select"] svg,
    [data-testid="stNumberInput"] button svg {
        color: #40566b !important;
        fill: #40566b !important;
    }
    [data-baseweb="popover"],
    [role="listbox"],
    [data-baseweb="menu"] {
        color: #172536 !important;
        background: #ffffff !important;
    }
    [role="option"] {
        color: #172536 !important;
        background: #ffffff !important;
    }
    [role="option"]:hover,
    [aria-selected="true"][role="option"] {
        background: #edf9f2 !important;
    }
    .stButton > button,
    .stDownloadButton > button,
    [data-testid="stFormSubmitButton"] > button {
        border-color: #b8c7d5 !important;
        color: #203247 !important;
        background: #ffffff !important;
    }
    .stButton > button:hover,
    .stDownloadButton > button:hover,
    [data-testid="stFormSubmitButton"] > button:hover {
        border-color: #0fa958 !important;
        color: #087a3e !important;
        background: #eefcf3 !important;
    }
    .stButton > button[kind="primary"],
    [data-testid="stFormSubmitButton"] > button[kind="primary"] {
        border-color: #0fa958 !important;
        color: #ffffff !important;
        background: #0fa958 !important;
    }
    .stButton > button:disabled,
    .stDownloadButton > button:disabled,
    [data-testid="stFormSubmitButton"] > button:disabled {
        border-color: #d7e0e8 !important;
        color: #94a3b1 !important;
        background: #edf1f5 !important;
    }
    .workflow-step {
        border-color: #d5e0e9;
        color: #172536;
        background: #ffffff;
        box-shadow: 0 4px 16px rgba(31, 52, 73, .05);
    }
    .workflow-step-number {
        color: #ffffff;
        background: #0fa958;
    }
    .workflow-step-title {
        color: #172536;
    }
    .workflow-step-desc {
        color: #60758a;
    }
    [data-testid="stCode"],
    [data-testid="stJson"],
    pre {
        border-color: #d8e2ec !important;
        color: #172536 !important;
        background: #ffffff !important;
    }
    .auth-page {
        color: #172536;
        background:
            linear-gradient(90deg, rgba(240, 249, 255, .18) 0%, rgba(240, 249, 255, .62) 48%, rgba(247, 250, 252, .98) 100%),
            url("/sub/assets/auth-future-city.png") center / cover fixed;
    }
    .auth-brand-mark,
    .auth-submit {
        color: #ffffff;
        background: #0fa958;
    }
    .auth-brand-name,
    .auth-intro h1,
    .auth-card h2 {
        color: #102338;
    }
    .auth-brand-desc,
    .auth-intro > p,
    .auth-card-subtitle,
    .auth-options,
    .auth-security,
    .auth-product-note {
        color: #52677b;
    }
    .auth-eyebrow,
    .auth-tab.active {
        color: #087a3e !important;
    }
    .auth-capability {
        color: #20364a;
        background: rgba(255, 255, 255, .84);
    }
    .auth-card {
        border-color: rgba(184, 204, 220, .95);
        background: rgba(255, 255, 255, .97);
        box-shadow: 0 26px 70px rgba(31, 52, 73, .18);
    }
    .auth-tab {
        color: #60758a !important;
    }
    .auth-tab.active {
        background: #edf9f2;
    }
    .auth-field {
        color: #40566b;
    }
    .auth-field input {
        border-color: #b8c9d8;
        color: #172536;
        background: #ffffff;
    }
    .auth-submit:hover {
        background: #0b914b;
    }
    .auth-security {
        border-top-color: #dce5ed;
    }
    .auth-registration-closed {
        border-color: #c8d5e0;
        color: #52677b;
        background: #f5f8fb;
    }
    /* 修正 Streamlit 默认顶部留白，并避免窄屏标签互相遮挡。 */
    [data-testid="stAppViewContainer"] > .main {
        padding-top: 0 !important;
    }
    .block-container {
        width: 100%;
        max-width: 1440px;
        padding-top: .55rem !important;
    }
    [data-testid="stSidebar"] > div:first-child {
        padding-top: .55rem !important;
    }
    div[data-baseweb="tab-list"] {
        width: 100%;
        overflow-x: auto;
        overflow-y: hidden;
        flex-wrap: nowrap;
        scrollbar-width: thin;
    }
    button[data-baseweb="tab"] {
        flex: 0 0 auto;
        white-space: nowrap;
    }
    button[data-baseweb="tab"] p {
        white-space: nowrap;
    }
    @media (max-width: 1100px) {
        .block-container {
            padding-right: 1rem !important;
            padding-left: 1rem !important;
        }
        button[data-baseweb="tab"] {
            padding-right: .5rem !important;
            padding-left: .5rem !important;
        }
        button[data-baseweb="tab"] p {
            font-size: .95rem;
        }
    }
    @media (max-width: 760px) {
        .block-container {
            padding-top: .35rem !important;
        }
    }
    /* Streamlit 顶部 Header 会形成透明点击遮罩，同时推低侧栏内容。 */
    [data-testid="stHeader"] {
        display: none !important;
        height: 0 !important;
        min-height: 0 !important;
        pointer-events: none !important;
    }
    [data-testid="stAppViewContainer"],
    [data-testid="stAppViewContainer"] > .main {
        top: 0 !important;
        margin-top: 0 !important;
        padding-top: 0 !important;
    }
    [data-testid="stSidebar"] {
        top: 0 !important;
        height: 100vh !important;
    }
    [data-testid="stSidebar"] > div,
    [data-testid="stSidebar"] > div:first-child,
    [data-testid="stSidebarContent"] {
        margin-top: 0 !important;
        padding-top: .5rem !important;
    }
    div[data-baseweb="tab-list"],
    button[data-baseweb="tab"] {
        position: relative;
        z-index: 2;
        pointer-events: auto !important;
    }
    /* 压缩主表单纵向节奏，保留控件可点击高度。 */
    [data-testid="stMainBlockContainer"] [data-testid="stVerticalBlock"] {
        gap: .62rem;
    }
    [data-testid="stMainBlockContainer"] [data-testid="stVerticalBlockBorderWrapper"] {
        margin-bottom: .15rem;
    }
    [data-testid="stMainBlockContainer"] [data-testid="stWidgetLabel"] {
        margin-bottom: .15rem;
    }
    [data-testid="stMainBlockContainer"] [data-testid="stWidgetLabel"] p {
        line-height: 1.3;
    }
    [data-testid="stMainBlockContainer"] .stHeadingContainer {
        margin-bottom: -.15rem;
    }
    [data-testid="stMainBlockContainer"] .workflow-step {
        margin-bottom: .45rem;
    }
    [data-testid="stMainBlockContainer"] hr {
        margin: .55rem 0;
    }
    [data-testid="stMainBlockContainer"] details summary {
        min-height: 42px;
        padding-top: .45rem;
        padding-bottom: .45rem;
    }
    /* 应用页最终主题：深色玻璃拟态，避免依赖 Tab DOM 顺序或 :has()。 */
    :root {
        color-scheme: dark;
    }
    .stApp {
        color: #e9f5f8;
        background:
            radial-gradient(circle at 12% 0%, rgba(34, 95, 151, .24), transparent 34rem),
            radial-gradient(circle at 88% 6%, rgba(24, 181, 116, .12), transparent 28rem),
            #070b12;
    }
    .stApp,
    .stApp p,
    .stApp label,
    .stApp h1,
    .stApp h2,
    .stApp h3,
    .stApp h4,
    .stApp h5,
    .stApp h6 {
        color: #e9f5f8;
    }
    [data-testid="stSidebar"] {
        background: rgba(6, 13, 23, .9);
        border-right-color: rgba(130, 174, 205, .18);
        backdrop-filter: blur(18px);
    }
    [data-testid="stSidebar"] *,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] label {
        color: #c8dbe4;
    }
    div[data-baseweb="tab-list"] {
        border-bottom-color: rgba(130, 174, 205, .2);
        background: rgba(8, 17, 29, .5);
        backdrop-filter: blur(14px);
    }
    button[data-baseweb="tab"] p {
        color: #8ea6b4;
    }
    button[data-baseweb="tab"][aria-selected="true"] p {
        color: #45ff7b;
    }
    .workflow-step,
    [data-testid="stMetric"],
    [data-testid="stExpander"] details,
    [data-testid="stAlertContainer"] {
        border: 1px solid rgba(128, 173, 205, .2) !important;
        border-radius: 8px !important;
        background: rgba(12, 25, 40, .68) !important;
        box-shadow: 0 14px 34px rgba(0, 0, 0, .2);
        backdrop-filter: blur(16px);
    }
    .workflow-step {
        gap: .6rem;
        margin: .1rem 0 .55rem;
        padding: .65rem .8rem;
    }
    .workflow-step-number {
        width: 1.6rem;
        height: 1.6rem;
        flex-basis: 1.6rem;
        color: #06111b;
        background: #45ff7b;
        font-size: .82rem;
    }
    .workflow-step-title {
        color: #effcff;
        font-size: .96rem;
        line-height: 1.25;
    }
    .workflow-step-desc {
        color: #91a8b6;
        font-size: .84rem;
        line-height: 1.35;
    }
    [data-testid="stMetric"] {
        min-height: 76px;
        padding: .58rem .7rem;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.22rem;
    }
    [data-testid="stMainBlockContainer"] details summary {
        min-height: 38px;
        padding-top: .32rem;
        padding-bottom: .32rem;
        color: #dcecf2;
    }
    [data-baseweb="input"],
    [data-baseweb="textarea"],
    [data-baseweb="select"] > div,
    [data-baseweb="base-input"],
    [data-testid="stNumberInput"] > div > div {
        border-color: rgba(110, 159, 193, .3) !important;
        background: rgba(9, 20, 33, .82) !important;
    }
    [data-baseweb="input"] input,
    [data-baseweb="textarea"] textarea,
    [data-baseweb="select"] input,
    [data-baseweb="select"] span {
        color: #e7f2f6 !important;
        background: transparent !important;
        -webkit-text-fill-color: #e7f2f6 !important;
    }
    [data-baseweb="select"] svg,
    [data-testid="stNumberInput"] button svg {
        color: #9bb1be !important;
        fill: #9bb1be !important;
    }
    [data-baseweb="popover"],
    [role="listbox"],
    [data-baseweb="menu"],
    [role="option"] {
        color: #e7f2f6 !important;
        background: #0c1826 !important;
    }
    [role="option"]:hover,
    [aria-selected="true"][role="option"] {
        background: #122c35 !important;
    }
    [data-testid="stCode"],
    [data-testid="stJson"],
    pre {
        border-color: rgba(110, 159, 193, .25) !important;
        color: #dcecf2 !important;
        background: rgba(5, 14, 24, .88) !important;
    }
    .stButton > button,
    .stDownloadButton > button,
    [data-testid="stFormSubmitButton"] > button {
        border-color: rgba(110, 159, 193, .38) !important;
        color: #e9f5f8 !important;
        background: rgba(17, 34, 51, .82) !important;
    }
    .stButton > button:hover,
    .stDownloadButton > button:hover,
    [data-testid="stFormSubmitButton"] > button:hover {
        border-color: #45ff7b !important;
        color: #45ff7b !important;
        background: rgba(11, 30, 40, .94) !important;
    }
    .stButton > button[kind="primary"],
    [data-testid="stFormSubmitButton"] > button[kind="primary"] {
        border-color: #45ff7b !important;
        color: #06111b !important;
        background: #45ff7b !important;
    }
    .stButton > button *,
    .stDownloadButton > button *,
    [data-testid="stFormSubmitButton"] > button * {
        color: inherit !important;
        -webkit-text-fill-color: currentColor !important;
    }
    button:disabled,
    button[disabled],
    .stButton > button:disabled,
    .stDownloadButton > button:disabled,
    [data-testid="stFormSubmitButton"] > button:disabled {
        border-color: #263847 !important;
        color: #8fa3af !important;
        background: #111b27 !important;
        opacity: 1 !important;
    }
    button:disabled *,
    button[disabled] * {
        color: #8fa3af !important;
        -webkit-text-fill-color: #8fa3af !important;
    }
    [data-testid="stSidebar"] .stButton > button,
    [data-testid="stSidebar"] .stDownloadButton > button,
    [data-testid="stSidebar"] [data-testid="stFormSubmitButton"] > button {
        border-color: #31495c !important;
        color: #e9f5f8 !important;
        background: #142231 !important;
    }
    [data-testid="stSidebar"] .stButton > button *,
    [data-testid="stSidebar"] .stDownloadButton > button *,
    [data-testid="stSidebar"] [data-testid="stFormSubmitButton"] > button * {
        color: inherit !important;
        -webkit-text-fill-color: currentColor !important;
    }
    [data-testid="stSidebar"] button:disabled,
    [data-testid="stSidebar"] button[disabled],
    [data-testid="stSidebar"] button[aria-disabled="true"] {
        border-color: #263a4a !important;
        color: #91a7b4 !important;
        background: #101b27 !important;
        opacity: 1 !important;
    }
    [data-testid="stSidebar"] button:disabled *,
    [data-testid="stSidebar"] button[disabled] *,
    [data-testid="stSidebar"] button[aria-disabled="true"] * {
        color: #91a7b4 !important;
        -webkit-text-fill-color: #91a7b4 !important;
    }
    [data-testid="stSidebar"] [data-baseweb="input"],
    [data-testid="stSidebar"] [data-baseweb="input"][aria-disabled="true"],
    [data-testid="stSidebar"] [data-baseweb="base-input"] {
        border-color: #2b4356 !important;
        background: #0d1925 !important;
        opacity: 1 !important;
    }
    [data-testid="stSidebar"] [data-baseweb="input"] input,
    [data-testid="stSidebar"] [data-baseweb="input"] input:disabled,
    [data-testid="stSidebar"] input[disabled],
    [data-testid="stSidebar"] input[readonly] {
        color: #a9bfca !important;
        background: #0d1925 !important;
        -webkit-text-fill-color: #a9bfca !important;
        opacity: 1 !important;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] details,
    [data-testid="stSidebar"] [data-testid="stExpander"] details > summary {
        border-color: #294155 !important;
        color: #d8e8ee !important;
        background: #0c1824 !important;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] details > summary * {
        color: #d8e8ee !important;
        -webkit-text-fill-color: #d8e8ee !important;
    }
    .import-source-row,
    .draft-status {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        margin-bottom: .45rem;
        padding: .65rem .75rem;
        border: 1px solid rgba(128, 173, 205, .2);
        border-radius: 8px;
        background: rgba(10, 23, 37, .66);
        backdrop-filter: blur(14px);
    }
    .import-source-row > div,
    .draft-status > div {
        display: flex;
        align-items: baseline;
        gap: .65rem;
        min-width: 0;
    }
    .import-source-row span,
    .draft-status span {
        color: #8fa6b4;
        font-size: .78rem;
    }
    .draft-status {
        margin: .1rem 0 .7rem;
        border-left: 3px solid #45ff7b;
    }
    .draft-status-pending {
        border-left-color: #ffbd4a;
    }
    .draft-status-pending strong {
        color: #ffcc72;
    }
    .draft-status-clean strong {
        color: #45ff7b;
    }
    .auth-card {
        border-color: rgba(94, 151, 187, .5);
        color: #e9f5f8;
        background: rgba(4, 15, 28, .82);
        box-shadow: 0 26px 70px rgba(0, 0, 0, .38);
        backdrop-filter: blur(20px);
    }
    .auth-brand-name,
    .auth-intro h1,
    .auth-card h2 {
        color: #effcff;
    }
    .auth-brand-desc,
    .auth-intro > p,
    .auth-card-subtitle,
    .auth-options,
    .auth-security,
    .auth-product-note {
        color: #94aab7;
    }
    .auth-field {
        color: #9fb3be;
    }
    .auth-field input {
        border-color: #28506d;
        color: #ecfaff;
        background: rgba(2, 12, 25, .76);
    }
    @media (max-width: 760px) {
        .draft-status,
        .import-source-row {
            align-items: flex-start;
            flex-direction: column;
            gap: .35rem;
        }
    }

    /* 2026 浅色玻璃主题：作为唯一最终覆盖层，保留现有 Streamlit 组件与业务行为。 */
    :root {
        color-scheme: light;
        --ui-ink: #0e1c2b;
        --ui-muted: #60758a;
        --ui-blue: #2468f2;
        --ui-green: #0db86b;
        --ui-amber: #e9930b;
        --ui-line: rgba(151, 177, 198, .42);
        --ui-glass: rgba(255, 255, 255, .7);
        --ui-glass-strong: rgba(255, 255, 255, .88);
        --ui-surface: #ffffff;
        --ui-bg: #eef6fb;
        --ui-shadow: 0 18px 42px rgba(41, 77, 105, .09);
    }
    html,
    body,
    [data-testid="stAppViewContainer"],
    .stApp {
        color: var(--ui-ink);
        background:
            linear-gradient(rgba(36, 104, 242, .035) 1px, transparent 1px),
            linear-gradient(90deg, rgba(36, 104, 242, .035) 1px, transparent 1px),
            radial-gradient(circle at 86% 8%, rgba(13, 184, 107, .11), transparent 28rem),
            radial-gradient(circle at 12% 0%, rgba(36, 104, 242, .12), transparent 34rem),
            var(--ui-bg);
        background-size: 72px 72px, 72px 72px, auto, auto, auto;
    }
    .stApp,
    .stApp p,
    .stApp label,
    .stApp h1,
    .stApp h2,
    .stApp h3,
    .stApp h4,
    .stApp h5,
    .stApp h6 {
        color: var(--ui-ink);
    }
    [data-testid="stMainBlockContainer"] {
        max-width: 1460px;
        padding: 1rem 1.4rem 5rem !important;
    }
    [data-testid="stSidebar"] {
        width: 270px !important;
        color: var(--ui-ink);
        border-right: 1px solid var(--ui-line);
        background: rgba(248, 252, 255, .82);
        box-shadow: 12px 0 34px rgba(41, 77, 105, .045);
        backdrop-filter: blur(24px);
    }
    [data-testid="stSidebar"] *,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] label {
        color: #34495d;
    }
    [data-testid="stSidebar"] > div,
    [data-testid="stSidebar"] > div:first-child,
    [data-testid="stSidebarContent"] {
        padding-top: .55rem !important;
    }
    .sidebar-brand {
        display: flex;
        align-items: center;
        gap: .7rem;
        margin: .1rem 0 1.25rem;
        padding: .72rem;
        border: 1px solid var(--ui-line);
        border-radius: 10px;
        background: var(--ui-glass);
        box-shadow: 0 10px 26px rgba(41, 77, 105, .07);
        backdrop-filter: blur(18px);
    }
    .sidebar-brand-mark {
        display: grid;
        place-items: center;
        width: 36px;
        height: 36px;
        flex: 0 0 36px;
        border-radius: 9px;
        color: #fff;
        background: linear-gradient(135deg, var(--ui-blue), var(--ui-green));
        font-weight: 850;
    }
    .sidebar-brand strong {
        display: block;
        color: var(--ui-ink);
        font-size: .78rem;
        line-height: 1.25;
    }
    .sidebar-brand span {
        display: block;
        margin-top: .16rem;
        color: var(--ui-muted);
        font-size: .66rem;
    }
    .sidebar-section-label {
        margin: .15rem .15rem .45rem;
        color: var(--ui-muted);
        font-size: .66rem;
        font-weight: 700;
    }
    [data-testid="stSidebar"] .workspace-nav {
        margin-bottom: .9rem;
    }
    [data-testid="stSidebar"] .workspace-nav + div [data-testid="stButton"] {
        margin-bottom: .22rem;
    }
    [data-testid="stSidebar"] .workspace-nav + div [data-testid="stButton"] > button {
        justify-content: flex-start;
        min-height: 38px;
        padding: .45rem .7rem;
        border-color: transparent !important;
        box-shadow: none;
    }
    [data-testid="stSidebar"] .workspace-nav + div [data-testid="stButton"] > button[kind="primary"] {
        border-color: rgba(36, 104, 242, .3) !important;
        color: #1456cf !important;
        background: rgba(226, 240, 255, .92) !important;
    }
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] > div:has(.sidebar-settings-collapsed) ~ div {
        display: none;
    }
    [data-testid="stSidebar"] .stHeadingContainer h1,
    [data-testid="stSidebar"] .stHeadingContainer h2,
    [data-testid="stSidebar"] .stHeadingContainer h3 {
        color: var(--ui-ink);
        font-size: 1rem;
    }
    [data-testid="stSidebar"] [data-baseweb="input"],
    [data-testid="stSidebar"] [data-baseweb="input"][aria-disabled="true"],
    [data-testid="stSidebar"] [data-baseweb="base-input"] {
        border-color: #c7d7e3 !important;
        background: rgba(255, 255, 255, .88) !important;
    }
    [data-testid="stSidebar"] [data-baseweb="input"] input,
    [data-testid="stSidebar"] [data-baseweb="input"] input:disabled,
    [data-testid="stSidebar"] input[disabled],
    [data-testid="stSidebar"] input[readonly] {
        color: #385066 !important;
        background: transparent !important;
        -webkit-text-fill-color: #385066 !important;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] details,
    [data-testid="stSidebar"] [data-testid="stExpander"] details > summary {
        border-color: var(--ui-line) !important;
        color: var(--ui-ink) !important;
        background: rgba(255, 255, 255, .62) !important;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] details > summary * {
        color: var(--ui-ink) !important;
        -webkit-text-fill-color: var(--ui-ink) !important;
    }
    [data-testid="stSidebar"] [data-testid="stAlertContainer"] {
        border-color: rgba(36, 104, 242, .18) !important;
        color: #24415a !important;
        background: rgba(232, 244, 255, .82) !important;
    }
    form.auth-logout-form button,
    [data-testid="stSidebar"] .stButton > button,
    [data-testid="stSidebar"] .stDownloadButton > button,
    [data-testid="stSidebar"] [data-testid="stFormSubmitButton"] > button {
        border-color: #c3d3df !important;
        color: #203247 !important;
        background: rgba(255, 255, 255, .9) !important;
    }
    [data-testid="stSidebar"] .stButton > button:hover,
    form.auth-logout-form button:hover {
        border-color: var(--ui-blue) !important;
        color: var(--ui-blue) !important;
        background: #f2f7ff !important;
    }
    [data-testid="stSidebar"] button:disabled,
    [data-testid="stSidebar"] button[disabled],
    [data-testid="stSidebar"] button[aria-disabled="true"] {
        border-color: #d7e1e9 !important;
        color: #8295a6 !important;
        background: #edf2f6 !important;
    }
    [data-testid="stSidebar"] button:disabled *,
    [data-testid="stSidebar"] button[disabled] *,
    [data-testid="stSidebar"] button[aria-disabled="true"] * {
        color: #8295a6 !important;
        -webkit-text-fill-color: #8295a6 !important;
    }
    .app-hero {
        display: flex;
        align-items: flex-end;
        justify-content: space-between;
        gap: 2rem;
        margin: 0 0 1rem;
        padding: 1rem 1.1rem 1.05rem;
        border: 1px solid var(--ui-line);
        border-radius: 12px;
        background: var(--ui-glass);
        box-shadow: var(--ui-shadow);
        backdrop-filter: blur(22px);
        animation: ui-enter .35s ease-out both;
    }
    .app-eyebrow {
        margin-bottom: .35rem;
        color: var(--ui-green);
        font-size: .66rem;
        font-weight: 800;
        text-transform: uppercase;
    }
    .app-hero h1 {
        margin: 0;
        color: var(--ui-ink);
        font-size: 1.75rem;
        line-height: 1.2;
    }
    .app-hero p {
        margin: .4rem 0 0;
        color: var(--ui-muted);
        font-size: .82rem;
    }
    .app-health {
        display: inline-flex;
        align-items: center;
        gap: .5rem;
        min-width: max-content;
        padding: .62rem .8rem;
        border: 1px solid rgba(13, 184, 107, .25);
        border-radius: 8px;
        color: #087747;
        background: rgba(231, 250, 241, .82);
        font-size: .72rem;
        font-weight: 750;
    }
    .app-health::before {
        content: "";
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--ui-green);
        animation: status-pulse 1.6s ease-in-out infinite;
    }
    .dashboard-workflow,
    .dashboard-panel,
    .dashboard-activity {
        border: 1px solid var(--ui-line);
        border-radius: 10px;
        background: var(--ui-glass);
        box-shadow: 0 12px 30px rgba(41, 77, 105, .06);
        backdrop-filter: blur(18px);
    }
    .dashboard-workflow {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .4rem;
        margin-bottom: .85rem;
        padding: .7rem;
    }
    .dashboard-step {
        position: relative;
        min-height: 58px;
        padding: .55rem .65rem;
        border: 1px solid transparent;
        border-radius: 8px;
    }
    .dashboard-step.active {
        border-color: rgba(13, 184, 107, .5);
        background: rgba(229, 249, 239, .74);
    }
    .dashboard-step small {
        margin-right: .55rem;
        color: var(--ui-muted);
        font-weight: 750;
    }
    .dashboard-step strong {
        color: var(--ui-ink);
        font-size: .78rem;
    }
    .dashboard-step span {
        display: block;
        margin: .3rem 0 0 2rem;
        color: var(--ui-muted);
        font-size: .67rem;
    }
    .dashboard-panel {
        min-height: 270px;
        padding: 1rem;
    }
    .dashboard-panel h3,
    .dashboard-activity h3 {
        margin: 0;
        color: var(--ui-ink);
        font-size: .96rem;
    }
    .dashboard-panel-subtitle {
        margin: .3rem 0 .9rem;
        color: var(--ui-muted);
        font-size: .68rem;
    }
    .dashboard-node-head,
    .dashboard-node-row {
        display: grid;
        grid-template-columns: minmax(0, 1.7fr) 1fr .55fr .45fr;
        align-items: center;
        gap: .5rem;
    }
    .dashboard-node-head {
        padding: 0 .6rem .4rem;
        color: var(--ui-muted);
        font-size: .65rem;
    }
    .dashboard-node-row {
        min-height: 48px;
        margin-bottom: .35rem;
        padding: .45rem .6rem;
        border-radius: 7px;
        background: rgba(244, 249, 253, .8);
        font-size: .7rem;
    }
    .dashboard-node-name {
        display: flex;
        align-items: center;
        gap: .55rem;
        min-width: 0;
        color: var(--ui-ink);
        font-weight: 700;
    }
    .dashboard-node-name::before {
        content: "";
        width: 7px;
        height: 7px;
        flex: 0 0 7px;
        border-radius: 50%;
        background: var(--ui-green);
    }
    .dashboard-node-source {
        overflow: hidden;
        color: var(--ui-muted);
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .dashboard-node-status {
        color: #087747;
        font-weight: 700;
    }
    .dashboard-node-protocol {
        color: var(--ui-muted);
        text-align: right;
    }
    .dashboard-publish-state {
        margin: .7rem 0 .9rem;
        padding: .75rem;
        border: 1px solid rgba(13, 184, 107, .28);
        border-radius: 8px;
        color: #087747;
        background: rgba(231, 250, 241, .72);
        font-size: .72rem;
        font-weight: 700;
    }
    .dashboard-diff-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: .45rem;
        margin-top: .65rem;
    }
    .dashboard-diff {
        padding: .6rem;
        border-radius: 7px;
        background: rgba(239, 246, 251, .9);
    }
    .dashboard-diff span {
        display: block;
        color: var(--ui-muted);
        font-size: .64rem;
    }
    .dashboard-diff strong {
        display: block;
        margin-top: .25rem;
        color: var(--ui-blue);
        font-size: .95rem;
    }
    .dashboard-activity {
        margin-top: .85rem;
        padding: 1rem;
    }
    .dashboard-activity-row {
        display: grid;
        grid-template-columns: 9rem 1fr 1.4fr;
        gap: .75rem;
        padding: .42rem 0;
        color: var(--ui-muted);
        font-size: .7rem;
    }
    .dashboard-activity-row strong {
        color: var(--ui-ink);
    }
    .dashboard-empty {
        padding: 2.8rem 1rem;
        color: var(--ui-muted);
        text-align: center;
        font-size: .75rem;
    }
    div[data-baseweb="tab-list"] {
        gap: .25rem;
        margin-bottom: .85rem;
        padding: .35rem;
        border: 1px solid var(--ui-line);
        border-radius: 10px;
        background: rgba(255, 255, 255, .64);
        box-shadow: 0 10px 28px rgba(41, 77, 105, .06);
        backdrop-filter: blur(18px);
    }
    button[data-baseweb="tab"] {
        min-height: 44px;
        padding: .55rem .75rem !important;
        border-radius: 7px;
    }
    button[data-baseweb="tab"] p {
        color: #63798d;
        font-size: .86rem;
        font-weight: 700;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        background: rgba(229, 247, 238, .92);
    }
    button[data-baseweb="tab"][aria-selected="true"] p {
        color: #087747;
    }
    button[data-baseweb="tab"][aria-selected="true"]::after {
        background-color: var(--ui-green) !important;
    }
    .workflow-step,
    [data-testid="stMetric"],
    [data-testid="stExpander"] details,
    [data-testid="stAlertContainer"],
    [data-testid="stDataFrame"],
    [data-testid="stTable"] {
        border: 1px solid var(--ui-line) !important;
        border-radius: 10px !important;
        color: var(--ui-ink) !important;
        background: var(--ui-glass) !important;
        box-shadow: 0 12px 30px rgba(41, 77, 105, .06);
        backdrop-filter: blur(18px);
    }
    .workflow-step {
        margin: .05rem 0 .55rem;
        padding: .72rem .85rem;
    }
    .workflow-step-number {
        color: #fff;
        background: linear-gradient(135deg, var(--ui-blue), var(--ui-green));
    }
    .workflow-step-title {
        color: var(--ui-ink);
    }
    .workflow-step-desc {
        color: var(--ui-muted);
    }
    [data-testid="stMetric"] {
        min-height: 84px;
        padding: .65rem .75rem;
    }
    [data-testid="stMetricLabel"] p {
        color: var(--ui-muted);
    }
    [data-testid="stMetricValue"] {
        color: var(--ui-ink);
    }
    [data-baseweb="input"],
    [data-baseweb="textarea"],
    [data-baseweb="select"] > div,
    [data-baseweb="base-input"],
    [data-testid="stNumberInput"] > div > div {
        border-color: #c5d5e1 !important;
        color: var(--ui-ink) !important;
        background: rgba(255, 255, 255, .9) !important;
    }
    [data-baseweb="input"] input,
    [data-baseweb="textarea"] textarea,
    [data-baseweb="select"] input,
    [data-baseweb="select"] span {
        color: var(--ui-ink) !important;
        background: transparent !important;
        -webkit-text-fill-color: var(--ui-ink) !important;
    }
    [data-baseweb="select"] svg,
    [data-testid="stNumberInput"] button svg {
        color: #40566b !important;
        fill: #40566b !important;
    }
    [data-baseweb="popover"],
    [role="listbox"],
    [data-baseweb="menu"],
    [role="option"] {
        color: var(--ui-ink) !important;
        background: #fff !important;
    }
    [role="option"]:hover,
    [aria-selected="true"][role="option"] {
        background: #edf5ff !important;
    }
    [data-testid="stCode"],
    [data-testid="stJson"],
    pre {
        border-color: #cfdae4 !important;
        color: #193047 !important;
        background: rgba(255, 255, 255, .92) !important;
    }
    .stButton > button,
    .stDownloadButton > button,
    [data-testid="stFormSubmitButton"] > button {
        min-height: 40px;
        border-color: #bfd0dd !important;
        color: #203247 !important;
        background: rgba(255, 255, 255, .9) !important;
        box-shadow: 0 6px 16px rgba(41, 77, 105, .045);
        transition: transform .16s ease, border-color .16s ease, box-shadow .16s ease;
    }
    .stButton > button:hover,
    .stDownloadButton > button:hover,
    [data-testid="stFormSubmitButton"] > button:hover {
        transform: translateY(-1px);
        border-color: var(--ui-blue) !important;
        color: var(--ui-blue) !important;
        background: #f3f7ff !important;
        box-shadow: 0 10px 22px rgba(36, 104, 242, .1);
    }
    .stButton > button[kind="primary"],
    [data-testid="stFormSubmitButton"] > button[kind="primary"] {
        border-color: var(--ui-blue) !important;
        color: #fff !important;
        background: linear-gradient(100deg, var(--ui-blue), var(--ui-green)) !important;
    }
    .stButton > button:disabled,
    .stDownloadButton > button:disabled,
    [data-testid="stFormSubmitButton"] > button:disabled {
        border-color: #d8e2ea !important;
        color: #8496a5 !important;
        background: #edf2f6 !important;
        opacity: 1 !important;
    }
    .stButton > button:disabled *,
    .stDownloadButton > button:disabled *,
    [data-testid="stFormSubmitButton"] > button:disabled * {
        color: #8496a5 !important;
        -webkit-text-fill-color: #8496a5 !important;
    }
    .import-source-row,
    .draft-status {
        border-color: var(--ui-line);
        color: var(--ui-ink);
        background: rgba(255, 255, 255, .7);
        box-shadow: 0 10px 24px rgba(41, 77, 105, .05);
    }
    .import-source-row span,
    .draft-status span {
        color: var(--ui-muted);
    }
    .draft-status-clean {
        border-left-color: var(--ui-green);
    }
    .draft-status-clean strong {
        color: #087747;
    }
    .draft-status-pending {
        border-left-color: var(--ui-amber);
    }
    .draft-status-pending strong {
        color: #a96200;
    }
    .auth-page {
        color: var(--ui-ink);
        background:
            linear-gradient(rgba(36, 104, 242, .045) 1px, transparent 1px),
            linear-gradient(90deg, rgba(36, 104, 242, .045) 1px, transparent 1px),
            radial-gradient(circle at 88% 10%, rgba(13, 184, 107, .14), transparent 28rem),
            radial-gradient(circle at 12% 0%, rgba(36, 104, 242, .14), transparent 34rem),
            #f1f8fc;
        background-size: 72px 72px, 72px 72px, auto, auto, auto;
    }
    .auth-page::before {
        background: linear-gradient(120deg, rgba(255,255,255,.2), rgba(255,255,255,.72));
        mask-image: none;
    }
    .auth-page::after {
        background: var(--ui-blue);
        box-shadow:
            13vw -9vh 0 var(--ui-blue),
            31vw -3vh 0 var(--ui-green),
            43vw -20vh 0 var(--ui-blue),
            57vw -11vh 0 var(--ui-green);
        filter: drop-shadow(0 0 9px rgba(36,104,242,.32));
    }
    .auth-layout {
        width: min(1320px, calc(100% - 64px));
        grid-template-columns: minmax(0, 1fr) 420px;
        gap: 64px;
    }
    .auth-brand-mark,
    .auth-submit {
        color: #fff;
        background: linear-gradient(135deg, var(--ui-blue), var(--ui-green));
    }
    .auth-brand-mark {
        border-radius: 10px;
        box-shadow: 0 12px 26px rgba(36, 104, 242, .16);
    }
    .auth-brand-name,
    .auth-intro h1,
    .auth-card h2 {
        color: var(--ui-ink);
    }
    .auth-brand-desc,
    .auth-intro > p,
    .auth-card-subtitle,
    .auth-options,
    .auth-security,
    .auth-product-note {
        color: var(--ui-muted);
    }
    .auth-eyebrow {
        margin-bottom: 1rem;
        color: var(--ui-green);
    }
    .auth-intro h1 {
        max-width: 690px;
        font-size: clamp(2.45rem, 4.2vw, 3.65rem);
        line-height: 1.14;
    }
    .auth-intro > p {
        margin: 1.25rem 0 1.5rem;
        line-height: 1.65;
    }
    .auth-capability {
        border-color: rgba(36, 104, 242, .16);
        color: #294158;
        background: rgba(255, 255, 255, .64);
        box-shadow: 0 8px 22px rgba(41, 77, 105, .055);
    }
    .auth-capability::before {
        background: var(--ui-green);
        box-shadow: 0 0 8px rgba(13, 184, 107, .32);
    }
    .auth-route-card {
        position: relative;
        height: 142px;
        margin-top: 1.6rem;
        overflow: hidden;
        border: 1px solid var(--ui-line);
        border-radius: 12px;
        background: rgba(255, 255, 255, .55);
        box-shadow: var(--ui-shadow);
        backdrop-filter: blur(18px);
    }
    .auth-route-card::before {
        content: "";
        position: absolute;
        inset: 0;
        background:
            radial-gradient(circle at 12% 55%, var(--ui-blue) 0 5px, transparent 6px),
            radial-gradient(circle at 38% 28%, var(--ui-blue) 0 5px, transparent 6px),
            radial-gradient(circle at 62% 62%, var(--ui-blue) 0 5px, transparent 6px),
            radial-gradient(circle at 86% 35%, var(--ui-green) 0 5px, transparent 6px),
            linear-gradient(26deg, transparent 18%, rgba(36,104,242,.36) 18.3% 18.8%, transparent 19.1%),
            linear-gradient(153deg, transparent 43%, rgba(36,104,242,.36) 43.3% 43.8%, transparent 44.1%);
        animation: route-shift 4s ease-in-out infinite alternate;
    }
    .auth-route-labels {
        position: absolute;
        right: 1rem;
        bottom: .8rem;
        left: 1rem;
        display: flex;
        justify-content: space-between;
        color: var(--ui-muted);
        font-size: .68rem;
    }
    .auth-route-labels strong {
        color: var(--ui-green);
    }
    .auth-metrics {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: .75rem;
        margin-top: 1rem;
    }
    .auth-metric {
        padding: .7rem .8rem;
        border-left: 2px solid rgba(36, 104, 242, .32);
    }
    .auth-metric strong {
        display: block;
        color: var(--ui-ink);
        font-size: 1.2rem;
    }
    .auth-metric span {
        color: var(--ui-muted);
        font-size: .7rem;
    }
    .auth-card {
        padding: 2rem;
        border-color: rgba(151, 177, 198, .55);
        border-radius: 14px;
        color: var(--ui-ink);
        background: rgba(255, 255, 255, .72);
        box-shadow: 0 28px 70px rgba(41, 77, 105, .16);
        backdrop-filter: blur(28px);
    }
    .auth-tabs {
        gap: .25rem;
        margin-bottom: 1.35rem;
        padding: .25rem;
        border-radius: 8px;
        background: rgba(227, 239, 248, .74);
    }
    .auth-tab {
        padding: .65rem .5rem;
        border: 0;
        border-radius: 6px;
        color: var(--ui-muted) !important;
    }
    .auth-tab.active {
        color: var(--ui-ink) !important;
        background: rgba(255, 255, 255, .9);
        box-shadow: 0 5px 12px rgba(41, 77, 105, .06);
    }
    .auth-field {
        color: #40566b;
    }
    .auth-field input {
        border-color: #bfd1df;
        color: var(--ui-ink);
        background: rgba(255, 255, 255, .88);
    }
    .auth-field input:focus {
        border-color: var(--ui-blue);
        box-shadow: 0 0 0 3px rgba(36, 104, 242, .1);
    }
    .auth-submit:hover {
        background: linear-gradient(135deg, #1b5de5, #0aa860);
        box-shadow: 0 12px 30px rgba(36, 104, 242, .16);
    }
    .auth-security {
        margin-top: 1.35rem;
        padding: .8rem;
        border: 1px solid rgba(13, 184, 107, .22);
        border-radius: 8px;
        color: #087747;
        background: rgba(231, 250, 241, .76);
    }
    .auth-registration-closed,
    .auth-error {
        border-color: #c8d5e0;
        color: #52677b;
        background: rgba(245, 248, 251, .9);
    }
    @keyframes ui-enter {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes status-pulse {
        0%, 100% { opacity: .55; transform: scale(.9); }
        50% { opacity: 1; transform: scale(1.12); }
    }
    @keyframes route-shift {
        from { transform: translate3d(-3px, 2px, 0); opacity: .76; }
        to { transform: translate3d(4px, -3px, 0); opacity: 1; }
    }
    @media (prefers-reduced-motion: reduce) {
        .app-hero,
        .app-health::before,
        .auth-route-card::before {
            animation: none;
        }
    }
    @media (max-width: 820px) {
        [data-testid="stMainBlockContainer"] {
            padding: .75rem .8rem 5.4rem !important;
        }
        .app-hero {
            align-items: flex-start;
            flex-direction: column;
            gap: .8rem;
            padding: .9rem;
        }
        .app-hero h1 {
            font-size: 1.55rem;
        }
        .app-health {
            width: 100%;
            box-sizing: border-box;
        }
        .auth-page {
            position: fixed;
        }
        .auth-layout {
            width: min(100% - 32px, 430px);
            min-height: auto;
            gap: 1rem;
            padding: 1rem 0 2rem;
        }
        .auth-intro {
            padding-top: .75rem;
        }
        .auth-intro h1 {
            font-size: 2rem;
        }
        .auth-intro > p {
            margin: .65rem 0 0;
        }
        .auth-route-card,
        .auth-metrics,
        .auth-capabilities,
        .auth-product-note {
            display: none;
        }
        .auth-card {
            padding: 1.35rem;
        }
        div[data-baseweb="tab-list"] {
            border-radius: 9px;
        }
        button[data-baseweb="tab"] {
            padding: .45rem .58rem !important;
        }
        button[data-baseweb="tab"] p {
            font-size: .78rem;
        }
        .dashboard-workflow {
            grid-template-columns: 1fr;
        }
        .dashboard-step {
            min-height: 46px;
        }
        .dashboard-node-head {
            display: none;
        }
        .dashboard-node-row {
            grid-template-columns: minmax(0, 1fr) auto;
        }
        .dashboard-node-source,
        .dashboard-node-protocol {
            display: none;
        }
        .dashboard-activity-row {
            grid-template-columns: 1fr;
            gap: .18rem;
        }
    }
    @media (min-width: 821px) {
        .st-key-workspace_tabs [data-baseweb="tab-list"] {
            display: none;
        }
    }
</style>
""", unsafe_allow_html=True)

# 主题覆盖独立于业务逻辑，便于仅迭代界面层而不影响 Streamlit 的控件状态和事件绑定。
ui_theme_path = Path(__file__).with_name("assets") / "ui_theme.css"
if ui_theme_path.is_file():
    st.markdown(
        f"<style>{ui_theme_path.read_text(encoding='utf-8')}</style>",
        unsafe_allow_html=True,
    )


# ==========================================
# 0.1 数据库初始化 + 登录注册门禁
# ==========================================
init_db()
ensure_admin_from_env()

if "auth_user" not in st.session_state:
    st.session_state.auth_user = None


def set_auth_user(user) -> None:
    st.session_state.auth_user = {
        "id": int(user["id"]),
        "username": user["username"],
        "is_admin": bool(user["is_admin"]),
    }
    st.session_state.pop("session_loaded_user_id", None)


if not st.session_state.auth_user:
    session_token = st.context.cookies.get("clash_config_gen_session", "")
    session_user = get_user_by_auth_session(session_token)
    if session_user:
        set_auth_user(session_user)


if not st.session_state.auth_user:
    render_auth_gate(BRAND_MARK_SVG, PROJECT_REPOSITORY_URL, MIHOMO_DOCUMENTATION_URL)
    st.stop()

st.query_params.clear()

def reset_global_widget_keys() -> None:
    """应用预设时清理侧边栏控件缓存，避免旧 widget 值覆盖新的 global_config。"""
    for key in list(st.session_state.keys()):
        if key.startswith("gc_"):
            del st.session_state[key]


def apply_full_client_dns_leak_preset() -> None:
    """完整客户端预设：由生成的 YAML 接管 DNS/TUN，重点防止本机 DNS 绕过代理。"""
    st.session_state.global_config.update({
        "include_global_compat": False,
        "include_inbound_ports": False,
        "include_controller": False,
        "include_router_options": False,
        "enable_core_options": True,
        "tcp_concurrent": True,
        "unified_delay": True,
        "geodata_mode": True,
        "enable_dns": True,
        "dns_listen": "0.0.0.0:7874",
        "dns_ipv6": False,
        "enhanced_mode": "fake-ip",
        "fake_ip_range": "198.18.0.1/16",
        "fake_ip_range6": "fc00::/18",
        "fake_ip_filter_mode": "blacklist",
        "default_nameserver": "223.5.5.5\n119.29.29.29",
        "nameserver": "https://dns.alidns.com/dns-query\nhttps://doh.pub/dns-query",
        "direct_nameserver": "223.5.5.5\n119.29.29.29",
        "proxy_server_nameserver": "223.5.5.5",
        "fallback": "",
        "dns_respect_rules": True,
        "openclash_preset": False,
        "enable_tun": True,
        "tun_stack": "mixed",
        "tun_auto_route": True,
        "tun_auto_detect_interface": True,
        "tun_dns_hijack": True,
        "tun_dns_hijack_value": "127.0.0.1:53",
        "tun_endpoint_independent_nat": True,
        "tun_auto_redirect": False,
        "tun_strict_route": True,
        "enable_sniffer": True,
        "sniff_override_dest": True,
        "sniffer_parse_pure_ip": True,
        "sniffer_force_dns_mapping": True,
        "profile_store_selected": True,
        "profile_store_fake_ip": True,
        "generation_profile": "desktop-full",
    })
    reset_global_widget_keys()
    st.session_state["target_mode"] = "全平台客户端 (PC/移动端)"


def apply_openclash_router_safe_preset() -> None:
    """软路由预设：订阅只负责节点和规则，DNS/TUN 留给 OpenClash 插件统一接管。"""
    st.session_state.global_config.update({
        "include_global_compat": False,
        "include_inbound_ports": False,
        "include_controller": False,
        "include_router_options": False,
        "enable_core_options": False,
        "enable_dns": False,
        "dns_respect_rules": False,
        "direct_nameserver": "",
        "proxy_server_nameserver": "",
        "enable_tun": False,
        "tun_dns_hijack": False,
        "tun_strict_route": False,
        "enable_sniffer": False,
        "sniff_override_dest": False,
        "sniffer_parse_pure_ip": False,
        "sniffer_force_dns_mapping": False,
        "openclash_preset": False,
        "profile_store_selected": False,
        "profile_store_fake_ip": False,
        "generation_profile": "openclash-router",
    })
    reset_global_widget_keys()
    st.session_state["target_mode"] = "OpenClash / 软路由"

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


def int_global_config(name: str, default: int, minimum: int = 0) -> int:
    try:
        value = int(st.session_state.global_config.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


def target_mode_from_global_config(global_config: dict) -> str:
    if global_config.get("is_desktop") is False or global_config.get("generation_profile") == "openclash-router":
        return "OpenClash / 软路由"
    return "全平台客户端 (PC/移动端)"


def migrate_global_defaults(global_config: dict, saved_global_config: dict) -> dict:
    """把旧默认值迁移到当前推荐值，避免老账号继续显示旧 UI 默认。"""
    migrated = dict(global_config)
    if saved_global_config.get("url_test_tolerance") in (None, 50):
        migrated["url_test_tolerance"] = 30
    if not saved_global_config.get("target_mode_user_selected"):
        migrated["generation_profile"] = "openclash-router"
        migrated["is_desktop"] = False
    return migrated


def draft_state_signature(
    proxies: list[dict],
    global_config: dict,
    custom_rules: list[str],
    custom_rule_providers: dict,
    selected_rule_type: str,
    import_sources: list[dict],
) -> str:
    payload = json.dumps(
        {
            "proxies": proxies,
            "global_config": global_config,
            "custom_rules": custom_rules,
            "custom_rule_providers": custom_rule_providers,
            "selected_rule_type": selected_rule_type,
            "import_sources": import_sources,
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def current_draft_signature() -> str:
    return draft_state_signature(
        st.session_state.proxies_data,
        st.session_state.global_config,
        st.session_state.custom_rules,
        st.session_state.custom_rule_providers,
        st.session_state.get("selected_rule_type", DEFAULT_RULE_TYPE),
        st.session_state.import_sources,
    )


def persist_current_draft(
    validation_status: str = "unknown",
    validation_message: str = "",
) -> None:
    source_counts: dict[str, int] = {}
    for proxy in st.session_state.proxies_data:
        source_id = str(proxy.get("_source_id") or "")
        if source_id:
            source_counts[source_id] = source_counts.get(source_id, 0) + 1
    for source in st.session_state.import_sources:
        source["node_count"] = source_counts.get(str(source.get("id") or ""), 0)

    save_user_draft(
        current_user["id"],
        st.session_state.proxies_data,
        st.session_state.global_config,
        st.session_state.custom_rules,
        st.session_state.custom_rule_providers,
        st.session_state.get("selected_rule_type", DEFAULT_RULE_TYPE),
        st.session_state.import_sources,
        validation_status=validation_status,
        validation_message=validation_message,
    )
    st.session_state.persisted_draft_signature = current_draft_signature()


def register_import_source(source_name: str, source_type: str, proxies: list[dict]) -> list[dict]:
    source_id = uuid.uuid4().hex
    imported_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    clean_name = source_name.strip() or source_type
    tagged_proxies = []
    for proxy in proxies:
        tagged = dict(proxy)
        tagged["_source_id"] = source_id
        tagged["_source_name"] = clean_name
        tagged["_origin_name"] = str(proxy.get("name", ""))
        tagged_proxies.append(tagged)
    st.session_state.import_sources.append(
        {
            "id": source_id,
            "name": clean_name,
            "type": source_type,
            "node_count": len(tagged_proxies),
            "imported_at": imported_at,
        }
    )
    return tagged_proxies


def config_summary(config: dict | None) -> dict[str, int]:
    config = config if isinstance(config, dict) else {}
    return {
        "nodes": len(config.get("proxies") or []),
        "groups": len(config.get("proxy-groups") or []),
        "providers": len(config.get("rule-providers") or {}),
        "rules": len(config.get("rules") or []),
    }


def extract_proxy_names(config: dict | None) -> list[str]:
    config = config if isinstance(config, dict) else {}
    return [
        str(proxy.get("name"))
        for proxy in config.get("proxies") or []
        if isinstance(proxy, dict) and proxy.get("name")
    ]


def normalize_hy2_hop_interval(raw_value: str) -> int:
    """OpenClash/mihomo 当前把 Hysteria2 hop-interval 按整数秒解析。"""
    value = str(raw_value or "").strip()
    if not value:
        return 30
    if value.isdigit():
        seconds = int(value)
        if seconds <= 0:
            raise ValueError("hop-interval 必须大于 0 秒")
        return seconds
    if "-" in value:
        left, right = [part.strip() for part in value.split("-", 1)]
        if not left.isdigit() or not right.isdigit():
            raise ValueError("随机跳跃间隔必须写成 5-25 这种纯数字范围")
        start = int(left)
        end = int(right)
        if start <= 0 or end <= 0 or start > end:
            raise ValueError("随机跳跃间隔范围必须大于 0，且左侧不能大于右侧")
        return start
    raise ValueError("hop-interval 只支持整数秒，兼容输入 5-25 时会自动取 5 秒")


# 初始化session state来存储节点
if 'proxies_data' not in st.session_state:
    st.session_state.proxies_data = []

if 'custom_rules' not in st.session_state:
    st.session_state.custom_rules = []

if 'custom_rule_providers' not in st.session_state:
    st.session_state.custom_rule_providers = {}

if 'import_sources' not in st.session_state:
    st.session_state.import_sources = []

if 'global_config' not in st.session_state:
    st.session_state.global_config = build_default_global_config()

current_user = st.session_state.auth_user
saved_config = get_user_config(current_user["id"])
if st.session_state.get("session_loaded_user_id") != current_user["id"]:
    # 切换账号时必须先回到干净默认态，再加载当前用户配置。
    # 否则新用户空配置会继续沿用上一位用户的 session_state，下载到错误账号的 YAML。
    st.session_state.proxies_data = saved_config.get("proxies") or []
    saved_global_config = saved_config.get("global_config") or {}
    st.session_state.global_config = build_default_global_config()
    st.session_state.global_config.update(saved_global_config)
    st.session_state.global_config = migrate_global_defaults(st.session_state.global_config, saved_global_config)
    if not st.session_state.global_config.get("optional_globals_v2"):
        st.session_state.global_config.update({
            "include_global_compat": False,
            "include_inbound_ports": False,
            "include_controller": False,
            "include_router_options": False,
            "enable_core_options": False,
            "enable_dns": False,
            "enable_sniffer": False,
            "openclash_preset": False,
            "dns_respect_rules": False,
            "profile_store_selected": False,
            "profile_store_fake_ip": False,
            "optional_globals_v2": True,
        })
    st.session_state.custom_rules = saved_config.get("custom_rules") or []
    st.session_state.custom_rule_providers = saved_config.get("custom_rule_providers") or {}
    st.session_state.import_sources = saved_config.get("import_sources") or []
    if saved_config.get("selected_rule_type"):
        st.session_state.selected_rule_type = saved_config["selected_rule_type"]
    elif "selected_rule_type" not in st.session_state:
        st.session_state.selected_rule_type = DEFAULT_RULE_TYPE
    st.session_state["target_mode"] = target_mode_from_global_config(st.session_state.global_config)
    st.session_state.persisted_draft_signature = current_draft_signature()
    st.session_state.pop("checked_draft_signature", None)
    st.session_state.pop("checked_draft_yaml", None)
    st.session_state.pop("checked_draft_warnings", None)
    reset_global_widget_keys()
    st.session_state.session_loaded_user_id = current_user["id"]

if not st.session_state.get("ui_defaults_v3_applied"):
    st.session_state.global_config = migrate_global_defaults(
        st.session_state.global_config,
        st.session_state.global_config,
    )
    st.session_state["target_mode"] = target_mode_from_global_config(st.session_state.global_config)
    if st.session_state.get("gc_url_test_tolerance") == 50:
        del st.session_state["gc_url_test_tolerance"]
    st.session_state.ui_defaults_v3_applied = True

WORKSPACE_TABS = {
    "控制台": "▦  控制台",
    "导入节点": "↓  导入节点",
    "节点管理": "◇  节点管理",
    "分流规则": "⌘  分流规则",
    "生成与检查": "✓  生成与检查",
}
if "workspace_tabs" not in st.session_state:
    st.session_state.workspace_tabs = "控制台"


def switch_workspace(tab_name: str) -> None:
    st.session_state.workspace_tabs = tab_name


# ==========================================
# 2. 侧边栏：认证 + 高级全局设置
# ==========================================
with st.sidebar:
    st.markdown(
        f"""
        <div class="sidebar-brand">
          <div class="sidebar-brand-mark">{BRAND_MARK_SVG}</div>
          <div>
            <strong>CLASH CONFIG GEN</strong>
            <span>配置工作台</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="sidebar-section-label workspace-nav">工作空间</div>',
        unsafe_allow_html=True,
    )
    for workspace_name, workspace_label in WORKSPACE_TABS.items():
        st.button(
            workspace_label,
            key=f"workspace_nav_{workspace_name}",
            type="primary" if st.session_state.workspace_tabs == workspace_name else "secondary",
            use_container_width=True,
            on_click=switch_workspace,
            args=(workspace_name,),
        )

    st.divider()
    st.header("账号")
    st.caption(f"当前用户: {current_user['username']}")
    subscription_url = f"{get_public_base_url()}/sub/{saved_config['token']}"

    # 使用两列布局：订阅链接 + 一键复制按钮
    col_url, col_copy = st.columns([4, 1])
    with col_url:
        st.text_input("订阅链接", value=subscription_url, key="subscription_url_view",
                     help="复制到 OpenClash 的订阅地址", disabled=True)
    with col_copy:
        st.write("")  # 对齐
        st.write("")
        if st.button("📋", key="copy_url_btn", help="一键复制订阅链接"):
            import streamlit.components.v1 as components
            copy_js = f"""
            <script>
            (async () => {{
                const text = {json.dumps(subscription_url)};
                const clipboard = window.parent?.navigator?.clipboard || navigator.clipboard;
                try {{
                    await clipboard.writeText(text);
                }} catch (error) {{
                    // 某些嵌入式浏览器会禁止 Clipboard API；保留旧浏览器降级路径。
                    const textarea = document.createElement('textarea');
                    textarea.value = text;
                    textarea.setAttribute('readonly', '');
                    textarea.style.position = 'fixed';
                    textarea.style.opacity = '0';
                    document.body.appendChild(textarea);
                    textarea.select();
                    document.execCommand('copy');
                    textarea.remove();
                }}
            }})();
            </script>
            """
            components.html(copy_js, height=0)
            st.toast("订阅链接已复制到剪贴板", icon="✅")

    if st.button("重置订阅 Token", help="旧订阅链接会立即失效，适合链接泄露后的应急处理"):
        reset_subscription_token(current_user["id"])
        st.success("订阅 Token 已重置。")
        st.rerun()
    st.markdown(
        f"""
        <form class="auth-logout-form" method="post" action="/sub/auth/logout">
          <input name="csrf_token" type="hidden" value="{html.escape(create_csrf_token('logout'), quote=True)}">
          <button type="submit">退出登录</button>
        </form>
        """,
        unsafe_allow_html=True,
    )

    if current_user["is_admin"]:
        with st.expander("用户管理", expanded=False):
            for user in list_users():
                cols = st.columns([2.2, 1, 1, 1])
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
                with cols[3]:
                    if not user["is_admin"]:
                        if st.button("删除", key=f"delete_user_{user['id']}", type="secondary"):
                            try:
                                delete_regular_user(int(user["id"]))
                                st.success(f"已删除用户 {user['username']}")
                                st.rerun()
                            except Exception as exc:
                                st.error(f"删除失败: {exc}")

    st.divider()
    show_global_settings = st.toggle(
        "⚙  全局设置",
        value=False,
        key="show_global_settings",
        help="按需展开生成模式、DNS、TUN 和控制器等高级设置。",
    )
    st.markdown(
        (
            '<div class="sidebar-settings-expanded"></div>'
            if show_global_settings
            else '<div class="sidebar-settings-collapsed"></div>'
        ),
        unsafe_allow_html=True,
    )
    st.header("全局设置")
    if "target_mode" not in st.session_state:
        st.session_state["target_mode"] = target_mode_from_global_config(st.session_state.global_config)
    
    # 目标环境选择
    st.info("💡 **请根据您的使用场景选择模式**")
    target_mode = st.radio(
        "生成模式", 
        ("OpenClash / 软路由", "全平台客户端 (PC/移动端)"),
        horizontal=False,
        key="target_mode",
        help="全平台客户端：适用于 Windows, macOS, Android, iOS 等独立运行的客户端，生成包含 TUN、DNS 的完整配置。\nOpenClash：精简配置，仅生成节点和策略，基础设置由插件接管。"
    )
    is_desktop = target_mode == "全平台客户端 (PC/移动端)"
    generation_profile = "desktop-full" if is_desktop else "openclash-router"
    st.caption(
        "当前模式会自动选择生成策略：手机 / PC 客户端输出完整客户端配置；"
        "OpenClash / 软路由只输出节点、策略组和规则，端口、DNS、控制器等由插件接管。"
    )

    with st.expander("🧭 DNS 防泄露预设", expanded=True):
        st.caption("桌面客户端预设会写入 DNS/TUN；OpenClash 预设会关闭这些字段，把 DNS 劫持和上游解析交给插件统一接管。")
        preset_col1, preset_col2 = st.columns(2)
        with preset_col1:
            if st.button(
                "完整客户端防泄露",
                use_container_width=True,
                help="适合 Clash Verge / mihomo 桌面客户端，由 YAML 接管 DNS、TUN 和嗅探能力。",
                on_click=apply_full_client_dns_leak_preset,
            ):
                st.success("已应用完整客户端防泄露预设。")
        with preset_col2:
            if st.button(
                "OpenClash 软路由安全",
                use_container_width=True,
                help="适合 OpenClash 订阅，只输出节点、策略组和规则，避免和插件接管的 DNS/端口/控制器字段冲突。",
                on_click=apply_openclash_router_safe_preset,
            ):
                st.success("已应用 OpenClash 软路由安全预设。")

    # --- 基础入站设置 ---
    if is_desktop:
        with st.expander("📡 端口与基础设置", expanded=False):
            include_inbound_ports = st.checkbox(
                "写入端口与基础入站字段",
                value=st.session_state.global_config.get("include_inbound_ports", False),
                help="未勾选时不向 YAML 写入 port、socks-port、mixed-port、allow-lan、bind-address、mode、log-level、ipv6 等全局字段。",
                key="gc_include_inbound_ports",
            )
            include_global_compat = st.checkbox(
                "兼容旧版 global: 包装字段",
                value=st.session_state.global_config.get("include_global_compat", False),
                help="仅当你的目标内核需要旧版 global: 结构时开启。",
                key="gc_include_global_compat",
            )
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
        include_inbound_ports = st.session_state.global_config.get("include_inbound_ports", False)
        include_global_compat = st.session_state.global_config.get("include_global_compat", False)
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
            include_controller = st.checkbox(
                "写入控制器与 Dashboard 字段",
                value=st.session_state.global_config.get("include_controller", False),
                help="未勾选时不写入 external-controller、secret、external-ui 等控制器字段。",
                key="gc_include_controller",
            )
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
        include_controller = st.session_state.global_config.get("include_controller", False)
        mode = st.session_state.global_config["mode"]
        log_level = st.session_state.global_config["log_level"]
        external_controller = st.session_state.global_config["external_controller"]
        secret = st.session_state.global_config["secret"]
        find_process_mode = st.session_state.global_config["find_process_mode"]

    with st.expander("📈 策略组测速", expanded=False):
        st.caption("写入 Auto - UrlTest 策略组，OpenClash、Nikki、Clash Verge、FlClash 会直接读取订阅 YAML 中的这些参数。")
        url_test_url = st.text_input(
            "测速地址",
            value=st.session_state.global_config.get("url_test_url", "http://cp.cloudflare.com/generate_204"),
            help="用于 url-test 连通性检测。推荐使用稳定、响应快的 204 地址。",
            key="gc_url_test_url",
        )
        col_urltest_1, col_urltest_2 = st.columns(2)
        with col_urltest_1:
            url_test_interval = st.number_input(
                "测速间隔 interval (秒)",
                min_value=1,
                max_value=86400,
                value=int_global_config("url_test_interval", 60, minimum=1),
                help="多久重新测速一次。60 表示每 60 秒测试一次节点连通性。",
                key="gc_url_test_interval",
            )
        with col_urltest_2:
            url_test_tolerance = st.number_input(
                "切换灵敏度 tolerance (毫秒)",
                min_value=0,
                max_value=10000,
                value=30 if int_global_config("url_test_tolerance", 30, minimum=0) == 50 else int_global_config("url_test_tolerance", 30, minimum=0),
                help="延迟差超过该值时才更倾向切换，值越小越灵敏。",
                key="gc_url_test_tolerance",
            )

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
        st.info("OpenClash / 软路由模式推荐让 OpenClash 插件统一接管 DNS。openclash-router 模板会强制忽略 DNS、TUN、端口、控制器、Sniffer、NTP 等运行时字段。")

    # --- 核心特性 ---
    if is_desktop:
        with st.expander("⚡ Meta 核心特性", expanded=False):
            enable_core_options = st.checkbox(
                "写入 Meta 核心特性字段",
                value=st.session_state.global_config.get("enable_core_options", False),
                help="未勾选时不写入 tcp-concurrent、unified-delay、geodata-mode、geodata-loader。",
                key="gc_enable_core_options",
            )
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
    else:
        enable_core_options = False
        tcp_concurrent = False
        unified_delay = False
        geodata_mode = False
        enable_sniffer = False
        sniff_override = False

    # OpenClash 插件会接管下列运行时字段，UI 不再暴露重复设置。
    include_router_options = False
    openclash_preset = False
    redir_port = st.session_state.global_config.get("redir_port", 7892)
    mixed_port_oc = mixed_port
    external_controller_oc = external_controller
    interface_name = ""
    tproxy_port = st.session_state.global_config.get("tproxy_port", 7895)
    keep_alive_idle = st.session_state.global_config.get("keep_alive_idle", 600)
    secret_oc = secret
    authentication = ""
    fake_ip_range6 = st.session_state.global_config.get("fake_ip_range6", "fc00::/18")
    fake_ip_filter_mode = st.session_state.global_config.get("fake_ip_filter_mode", "blacklist")
    dns_respect_rules = st.session_state.global_config.get("dns_respect_rules", False) if is_desktop else False
    direct_nameserver = st.session_state.global_config.get("direct_nameserver", "")
    proxy_server_nameserver = st.session_state.global_config.get("proxy_server_nameserver", "")
    tun_dns_hijack_value = st.session_state.global_config.get("tun_dns_hijack_value", "127.0.0.1:53")
    tun_endpoint_independent_nat = st.session_state.global_config.get("tun_endpoint_independent_nat", False) if is_desktop else False
    tun_auto_redirect = st.session_state.global_config.get("tun_auto_redirect", False) if is_desktop else False
    tun_strict_route = st.session_state.global_config.get("tun_strict_route", False) if is_desktop else False
    sniffer_parse_pure_ip = st.session_state.global_config.get("sniffer_parse_pure_ip", False) if is_desktop else False
    sniffer_force_dns_mapping = st.session_state.global_config.get("sniffer_force_dns_mapping", False) if is_desktop else False
    profile_store_selected = st.session_state.global_config.get("profile_store_selected", False) if is_desktop else False
    profile_store_fake_ip = st.session_state.global_config.get("profile_store_fake_ip", False) if is_desktop else False
    ntp_enable = False
    ntp_server = st.session_state.global_config.get("ntp_server", "time.apple.com")
    ntp_port = st.session_state.global_config.get("ntp_port", 123)
    ntp_interval = st.session_state.global_config.get("ntp_interval", 30)
    ntp_write_to_system = False

# 更新 Session State
effective_mixed_port = mixed_port_oc if not is_desktop else mixed_port
effective_external_controller = external_controller_oc if not is_desktop else external_controller
updated_secret = secret_oc if not is_desktop else st.session_state.get('gc_secret', st.session_state.global_config["secret"])
st.session_state.global_config.update({
    "include_global_compat": include_global_compat,
    "include_inbound_ports": include_inbound_ports,
    "include_controller": include_controller,
    "include_router_options": include_router_options,
    "enable_core_options": enable_core_options,
    "port": port, "socks_port": socks_port, "mixed_port": effective_mixed_port,
    "allow_lan": allow_lan, "bind_address": bind_address, "mode": mode,
    "log_level": log_level, "ipv6_support": ipv6_support,
    "external_controller": effective_external_controller, "secret": updated_secret,
    "keep_alive_interval": keep_alive, "tcp_concurrent": tcp_concurrent,
    "url_test_url": url_test_url,
    "url_test_interval": int(url_test_interval),
    "url_test_tolerance": int(url_test_tolerance),
    "enable_tun": enable_tun, "unified_delay": unified_delay, "find_process_mode": find_process_mode,
    "geodata_mode": geodata_mode, "enable_sniffer": enable_sniffer, "sniff_override_dest": sniff_override,
    "openclash_preset": openclash_preset, "is_desktop": is_desktop,
    "redir_port": redir_port,
    "tproxy_port": tproxy_port,
    "interface_name": interface_name,
    "keep_alive_idle": keep_alive_idle,
    "authentication": authentication,
    "fake_ip_range6": fake_ip_range6,
    "fake_ip_filter_mode": fake_ip_filter_mode,
    "dns_respect_rules": dns_respect_rules,
    "direct_nameserver": direct_nameserver,
    "proxy_server_nameserver": proxy_server_nameserver,
    "tun_dns_hijack_value": tun_dns_hijack_value,
    "tun_endpoint_independent_nat": tun_endpoint_independent_nat,
    "tun_auto_redirect": tun_auto_redirect,
    "tun_strict_route": tun_strict_route,
    "sniffer_parse_pure_ip": sniffer_parse_pure_ip,
    "sniffer_force_dns_mapping": sniffer_force_dns_mapping,
    "profile_store_selected": profile_store_selected,
    "profile_store_fake_ip": profile_store_fake_ip,
    "ntp_enable": ntp_enable,
    "ntp_server": ntp_server,
    "ntp_port": ntp_port,
    "ntp_interval": ntp_interval,
    "ntp_write_to_system": ntp_write_to_system,
    "generation_profile": generation_profile,
    "target_mode_user_selected": True,
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
def render_workflow_step(step: int, title: str, description: str) -> None:
    st.markdown(
        f"""
<div class="workflow-step">
  <span class="workflow-step-number">{step}</span>
  <div>
    <p class="workflow-step-title">{title}</p>
    <p class="workflow-step-desc">{description}</p>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


selected_rule = st.session_state.get("selected_rule_type", DEFAULT_RULE_TYPE)
try:
    workspace_draft_config = build_subscription_config(
        st.session_state.proxies_data,
        st.session_state.global_config,
        st.session_state.custom_rules,
        st.session_state.custom_rule_providers,
        selected_rule,
    ) if st.session_state.proxies_data else {}
    workspace_draft_yaml = (
        build_subscription_yaml(workspace_draft_config)
        if workspace_draft_config
        else ""
    )
    workspace_draft_error = ""
except Exception as exc:
    workspace_draft_config = {}
    workspace_draft_yaml = ""
    workspace_draft_error = str(exc)

try:
    workspace_published_config = yaml.safe_load(saved_config.get("final_yaml") or "") or {}
except Exception:
    workspace_published_config = {}

workspace_draft_stats = config_summary(workspace_draft_config)
workspace_published_stats = config_summary(workspace_published_config)
workspace_has_changes = workspace_draft_yaml != (saved_config.get("final_yaml") or "")
workspace_checked = (
    st.session_state.get("checked_draft_signature") == current_draft_signature()
    and bool(st.session_state.get("checked_draft_yaml"))
)
workspace_status = (
    "待检查"
    if workspace_draft_error
    else "已通过"
    if workspace_checked
    else "有变更"
    if workspace_has_changes
    else "已同步"
)
workspace_published_at = (
    saved_config.get("published_at")
    or saved_config.get("validated_at")
    or "尚未发布"
)

st.markdown(
    """
    <section class="app-hero">
      <div>
        <div class="app-eyebrow">CONFIGURATION INTELLIGENCE</div>
        <h1>配置工作台</h1>
        <p>管理草稿、检查差异，并安全发布订阅。</p>
      </div>
      <div class="app-health">生产服务运行正常</div>
    </section>
    """,
    unsafe_allow_html=True,
)


dashboard_tab, tab1, tab2, tab3, tab4 = st.tabs(
    list(WORKSPACE_TABS),
    default=st.session_state.workspace_tabs,
    key="workspace_tabs",
    on_change="rerun",
)

with dashboard_tab:
    workflow_active_step = 3 if workspace_checked else 4 if not workspace_has_changes else 1
    workflow_steps = (
        ("01", "导入节点", f"{len(st.session_state.proxies_data)} 个节点"),
        ("02", "整理节点", f"{len(st.session_state.proxies_data)} 个可用"),
        ("03", "检查草稿", workspace_status),
        ("04", "发布订阅", "已同步" if not workspace_has_changes else "待确认"),
    )
    workflow_html = "".join(
        (
            f'<div class="dashboard-step{" active" if index == workflow_active_step else ""}">'
            f"<small>{number}</small><strong>{html.escape(title)}</strong>"
            f"<span>{html.escape(detail)}</span></div>"
        )
        for index, (number, title, detail) in enumerate(workflow_steps, start=1)
    )
    st.markdown(
        f'<div class="dashboard-workflow">{workflow_html}</div>',
        unsafe_allow_html=True,
    )

    dashboard_metrics = st.columns(4)
    dashboard_metrics[0].metric("节点", workspace_draft_stats["nodes"])
    dashboard_metrics[1].metric("策略组", workspace_draft_stats["groups"])
    dashboard_metrics[2].metric("规则", workspace_draft_stats["rules"])
    dashboard_metrics[3].metric(
        "发布状态",
        "草稿" if workspace_has_changes else "已发布",
    )

    nodes_column, publish_column = st.columns([1.6, 1])
    with nodes_column:
        node_rows = []
        for proxy in st.session_state.proxies_data[:5]:
            node_name = html.escape(str(proxy.get("name") or "未命名节点"))
            protocol = html.escape(str(proxy.get("type") or "unknown"))
            node_rows.append(
                '<div class="dashboard-node-row">'
                f'<div class="dashboard-node-name">{node_name}</div>'
                '<div class="dashboard-node-status">可用</div>'
                f'<div class="dashboard-node-protocol">{protocol}</div>'
                '</div>'
            )
        node_content = "".join(node_rows) or (
            '<div class="dashboard-empty">暂无节点，请先导入节点。</div>'
        )
        st.markdown(
            '<section class="dashboard-panel">'
            '<h3>节点概览</h3>'
            '<div class="dashboard-panel-subtitle">显示当前草稿中的节点与协议状态</div>'
            '<div class="dashboard-node-head">'
            '<span>节点</span><span>状态</span><span>协议</span>'
            '</div>'
            f'{node_content}'
            '</section>',
            unsafe_allow_html=True,
        )
        if len(st.session_state.proxies_data) > 5:
            st.caption(f"另有 {len(st.session_state.proxies_data) - 5} 个节点，请进入节点管理查看。")

    with publish_column:
        node_delta = workspace_draft_stats["nodes"] - workspace_published_stats["nodes"]
        rule_delta = workspace_draft_stats["rules"] - workspace_published_stats["rules"]
        provider_delta = (
            workspace_draft_stats["providers"]
            - workspace_published_stats["providers"]
        )
        publish_state = (
            "草稿与线上一致"
            if not workspace_has_changes
            else "草稿等待检查"
            if not workspace_checked
            else "草稿已检查，可以发布"
        )
        st.markdown(
            f"""
            <section class="dashboard-panel">
              <h3>草稿与发布</h3>
              <div class="dashboard-panel-subtitle">线上版本与当前草稿严格分离</div>
              <div class="dashboard-publish-state">{html.escape(publish_state)}</div>
              <strong>发布差异</strong>
              <div class="dashboard-diff-grid">
                <div class="dashboard-diff"><span>节点</span><strong>{node_delta:+d}</strong></div>
                <div class="dashboard-diff"><span>规则</span><strong>{rule_delta:+d}</strong></div>
                <div class="dashboard-diff"><span>规则集</span><strong>{provider_delta:+d}</strong></div>
              </div>
            </section>
            """,
            unsafe_allow_html=True,
        )
        publish_actions = st.columns(2)
        publish_actions[0].button(
            "检查草稿",
            use_container_width=True,
            key="dashboard_check_draft",
            on_click=switch_workspace,
            args=("生成与检查",),
        )
        publish_actions[1].button(
            "前往发布",
            type="primary",
            use_container_width=True,
            key="dashboard_publish_draft",
            on_click=switch_workspace,
            args=("生成与检查",),
        )

    activity_rows = [
        (
            "当前草稿",
            workspace_status,
            f"{workspace_draft_stats['nodes']} 个节点 · {workspace_draft_stats['rules']} 条规则",
        ),
        (
            "最近发布",
            "线上订阅",
            str(workspace_published_at),
        ),
        (
            "节点配置",
            f"{len(st.session_state.proxies_data)} 个节点",
            f"{len(set(str(proxy.get('type') or 'unknown') for proxy in st.session_state.proxies_data))} 种协议",
        ),
    ]
    activity_html = "".join(
        (
            '<div class="dashboard-activity-row">'
            f"<span>{html.escape(label)}</span>"
            f"<strong>{html.escape(value)}</strong>"
            f"<span>{html.escape(detail)}</span>"
            "</div>"
        )
        for label, value, detail in activity_rows
    )
    st.markdown(
        f"""
        <section class="dashboard-activity">
          <h3>状态摘要</h3>
          <div class="dashboard-panel-subtitle">仅显示当前配置流程的真实状态</div>
          {activity_html}
        </section>
        """,
        unsafe_allow_html=True,
    )

with tab1:
    render_workflow_step(
        1,
        "导入节点",
        "批量导入或手动添加节点，系统会统一解析、去重并校验节点字段。",
    )
    st.info(
        "这里统一处理完整 config.yaml、proxies: 片段、纯节点列表、onekey 输出片段、"
        "Base64 订阅内容和 URI 链接列表。订阅链接和分享链接保留独立入口，避免把远程拉取和本地粘贴混在一起。"
    )
    default_yaml = """
- name: "示例节点-SS"
  type: ss
  server: "1.2.3.4"
  port: 8888
  cipher: "2022-blake3-aes-128-gcm"
  password: "your_password"
  udp: true
"""

    import_method = st.radio(
        "选择导入方式",
        ("智能 YAML 导入", "订阅链接", "分享链接", "手动添加"),
        horizontal=True,
        help="四种录入方式最终进入同一套解析、去重和字段校验流程。",
    )

    # 旧草稿仍保留来源元数据以兼容存储结构，但界面不再要求用户维护重复的来源名称。
    source_name = {
        "智能 YAML 导入": "YAML 导入",
        "订阅链接": "远程订阅",
        "分享链接": "分享链接",
        "手动添加": "手动添加",
    }[import_method]
    raw_yaml_input = ""
    subscription_url = ""
    share_link = ""
    if import_method == "智能 YAML 导入":
        raw_yaml_input = st.text_area(
            "粘贴 YAML / OpenClash / onekey 输出片段",
            value=default_yaml.strip(),
            height=340,
            help="支持完整 Clash/OpenClash 配置、proxies: 块、纯 - name: 节点列表、onekey.sh 打印的多个 OpenClash YAML 配置片段，以及常见缩进错误的自动修复。",
        )
    elif import_method == "订阅链接":
        subscription_url = st.text_input(
            "输入订阅链接",
            placeholder="https://example.com/sub/xxxxx",
            help="如果这里返回的是 Streamlit/HTML 页面，说明 /sub/ 被反代到了 Web UI，而不是 FastAPI API 端口。",
        )
    elif import_method == "分享链接":
        share_link = st.text_area(
            "输入分享链接",
            placeholder="ss://... 或 vless://...，多条链接可一行一条",
            height=140,
            help="支持 ss、trojan、vmess、vless、tuic、hysteria2/hy2、anytls 等常见分享链接。",
        )

    if import_method != "手动添加" and st.button(
        "解析并加入草稿",
        key="import_proxies",
        type="primary",
        help="解析当前来源，完成去重和字段校验后加入草稿；不会立即发布订阅。",
    ):
        try:
            if import_method == "订阅链接":
                if not subscription_url.strip():
                    raise ValueError("请输入订阅链接")
                response_text, content_type = fetch_text_from_external_url(subscription_url, timeout=15)
                raw_yaml_input = normalize_subscription_content(response_text, content_type)
            elif import_method == "分享链接":
                parsed_links = []
                for line in share_link.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parsed_links.append(parse_share_link(line))
                if not parsed_links:
                    raise ValueError("请输入至少一条有效分享链接")
                raw_yaml_input = yaml.dump(
                    parsed_links,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=False,
                )
            if not raw_yaml_input.strip():
                raise ValueError("没有可导入的内容")

            input_proxies, import_warnings = parse_proxy_yaml(raw_yaml_input)
            existing_names = {proxy.get("name") for proxy in st.session_state.proxies_data}
            new_proxies = []
            for proxy in input_proxies:
                if proxy["name"] in existing_names:
                    st.warning(f"节点 '{proxy['name']}' 已存在，跳过重复添加")
                    continue
                new_proxies.append(proxy)
                existing_names.add(proxy["name"])

            source_type = {
                "智能 YAML 导入": "yaml",
                "订阅链接": "url",
                "分享链接": "share",
            }[import_method]
            if not new_proxies:
                st.info("本次没有可加入的节点。")
            else:
                tagged_proxies = register_import_source(source_name, source_type, new_proxies)
                st.session_state.proxies_data.extend(tagged_proxies)
                st.success(f"已加入草稿：{len(tagged_proxies)} 个新节点。")
            for warning in import_warnings:
                st.warning(warning)
        except Exception as e:
            st.error(f"导入失败: {e}")
            if import_method == "订阅链接":
                st.info("确认远程地址返回 YAML 或节点订阅，并检查反向代理路径是否正确。")

    if import_method == "手动添加":
        render_workflow_step(
            1,
            "手动添加节点",
            "按协议填写基础字段；高级参数按需展开，添加前仍会经过统一 YAML 校验。",
        )
    
        # 节点类型选择
        node_type = st.selectbox("选择节点类型", ["ss", "vless", "vmess", "trojan", "anytls", "tuic", "hysteria2"], help="选择要添加的代理节点类型")
    
        # 通用字段
        col1, col2 = st.columns(2)
        with col1:
            node_name = st.text_input("节点名称", f"My-{node_type.title()}", help="给节点起一个便于识别的名称")
            node_server = st.text_input("服务器地址", "example.com", help="代理服务器的地址")
        with col2:
            node_port = st.number_input("端口", min_value=1, max_value=65535, value=443, help="代理服务器的端口号")
            if node_type not in ["tuic", "hysteria2"]:  # tuic和hy2协议有单独的配置或不需要此通用UDP开关
                node_udp = st.checkbox("UDP 支持", value=True, key=f"node_udp_{node_type}", help="是否启用UDP转发")

        # 通用高级字段仅对 ss、vless、vmess 协议显示
        if node_type in ["ss", "vless", "vmess"]:
            with st.expander("通用高级字段", expanded=False):
                col_common1, col_common2 = st.columns(2)
                with col_common1:
                    common_ip_version = st.selectbox(
                        "ip-version",
                        ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"],
                        index=0,
                        key=f"common_ip_version_{node_type}",
                        help="mihomo 公共字段；默认不写入，避免和核心自动选择冲突。",
                    )
                with col_common2:
                    enable_smux = st.checkbox("smux", value=False, key=f"enable_smux_{node_type}", help="mihomo 通用复用配置，适用于支持 TCP 传输的 VMess / VLESS / Shadowsocks 等节点。")
                    smux_enabled = st.checkbox("smux.enabled", value=True, key=f"smux_enabled_{node_type}") if enable_smux else False
                    smux_protocol = st.selectbox("smux.protocol", ["h2mux", "yamux", "smux"], index=0, key=f"smux_protocol_{node_type}") if enable_smux else "h2mux"
                    smux_max_connections = st.number_input("smux.max-connections", min_value=1, value=4, key=f"smux_max_conn_{node_type}") if enable_smux else 4
                    smux_brutal_enabled = st.checkbox("smux.brutal-opts.enabled", value=node_type == "vless", key=f"smux_brutal_enabled_{node_type}") if enable_smux else False
                    smux_brutal_up = st.number_input("brutal up Mbps", min_value=1, value=100, key=f"smux_brutal_up_{node_type}") if enable_smux and smux_brutal_enabled else 100
                    smux_brutal_down = st.number_input("brutal down Mbps", min_value=1, value=100, key=f"smux_brutal_down_{node_type}") if enable_smux and smux_brutal_enabled else 100
        else:
            # 其他协议不显示通用高级字段，设置默认值避免后续引用报错
            common_ip_version = "默认"
            enable_smux = False
            smux_enabled = False
            smux_protocol = "h2mux"
            smux_max_connections = 4
            smux_brutal_enabled = False
            smux_brutal_up = 100
            smux_brutal_down = 100
    
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
                ], index=5, help="Shadowsocks协议的加密方式；onekey 默认使用 2022-blake3-aes-128-gcm。")
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
                hy2_sni = st.text_input("SNI", "www.bing.com", help="TLS握手时的服务器名称指示；onekey 默认伪装为 www.bing.com。")
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
        
            enable_port_hopping = st.checkbox("启用端口跳跃", value=True, key=f"enable_port_hopping_{node_type}", help="启用后写入 ports 字段；mihomo 会忽略 port 并按端口范围跳跃。")
            if enable_port_hopping:
                port_hopping_range = st.text_input("端口范围", "29950-30000", help="端口跳跃的范围；兼容 onekey 的 ports 字段。")
        
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
        
            hy2_hop_interval = st.text_input(
                "跳跃间隔（单位：秒）",
                value="30",
                help="OpenClash/mihomo 会按整数秒读取 hop-interval。兼容输入 5-25，但保存时会自动取左侧 5 秒，避免内核解析失败。",
            )
            hy2_fingerprint = st.selectbox("Client Fingerprint", ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "none"], index=0, help="TLS 客户端指纹；mihomo 必须写入 client-fingerprint，不能写入 fingerprint。")
            hy2_ip_version = st.selectbox("IP Version", ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"], index=0, help="使用的IP协议版本，默认不设置")
    
        elif node_type == "tuic":
            col3, col4 = st.columns(2)
            with col3:
                tuic_uuid = st.text_input("UUID", "00000000-0000-4000-8000-000000000000", help="TUIC协议的用户UUID")
                tuic_password = st.text_input("Password", type="password", help="TUIC协议的密码")
                tuic_server_ip = st.text_input("Server IP", "1.2.3.4", help="服务器IP地址")
            with col4:
                tuic_congestion = st.selectbox("Congestion Controller", ["bbr", "cubic", "new_reno", "bbr2", "none"], index=0, help="拥塞控制算法；onekey 默认使用 bbr。")
                tuic_alpn = st.selectbox("ALPN", ["h3", "h3-29", "h3-27"], index=0, help="应用层协议协商标识")
                tuic_udp_relay_mode = st.selectbox("UDP Relay Mode", ["native", "quic"], index=0, help="UDP中继模式")
        
            # 将高级设置提出来
            tuic_heartbeat_interval = st.number_input("心跳间隔 (毫秒)", value=10000, help="Application Layer 心跳间隔")

            tuic_close_sni = st.checkbox("关闭 SNI 服务器名称指示", value=False, key=f"tuic_close_sni_{node_type}", help="是否关闭SNI服务器名称指示")
            tuic_reduce_rtt = st.checkbox("Reduce RTT", value=True, key=f"tuic_reduce_rtt_{node_type}", help="是否启用0-RTT握手")
            tuic_skip_cert_verify = st.checkbox("跳过证书验证", value=True, key=f"tuic_skip_cert_verify_{node_type}", help="是否跳过TLS证书验证")
            tuic_fast_open = st.checkbox("快速打开", value=True, key=f"tuic_fast_open_{node_type}", help="是否启用快速打开")
            tuic_ip_version = st.selectbox("IP Version", ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"], index=0, help="使用的IP协议版本，默认不设置")
    
        elif node_type == "vless":
            col3, col4 = st.columns(2)
            with col3:
                node_uuid = st.text_input("UUID", "your-uuid-here", help="VLESS协议的用户UUID")
                vless_tls = st.checkbox("TLS", value=True, key=f"vless_tls_{node_type}", help="是否启用TLS加密")
            with col4:
                vless_flow = st.selectbox("flow (reality)", ["none", "xtls-rprx-vision", "xtls-rprx-vision-udp443"], index=1, help="XTLS 的流量特征；VLESS Reality 默认使用 xtls-rprx-vision。")
                vless_servername = st.text_input("servername", "v1-dy.ixigua.com", help="TLS握手时的服务器名称；onekey Reality 默认使用该伪装域名。")
        
            vless_network = st.selectbox("传输协议", ["tcp", "kcp", "ws", "h2", "grpc", "http"], index=0, help="传输层协议")
            vless_packet_encoding = st.text_input("Packet-Encoding", "", help="数据包编码方式")
            if vless_network == "ws":
                vless_ws_path = st.text_input("WebSocket path", "/vless", help="VLESS WS 的 ws-opts.path，兼容 OpenClash/mihomo。")
                vless_ws_host = st.text_input("WebSocket Host", "", help="需要伪装 Host 时填写，留空不写入 headers。")
            elif vless_network == "grpc":
                vless_grpc_service_name = st.text_input("gRPC service-name", "grpc", help="VLESS gRPC 的 grpc-opts.grpc-service-name。")
                vless_ws_path = ""
                vless_ws_host = ""
            else:
                vless_ws_path = ""
                vless_ws_host = ""
                vless_grpc_service_name = ""
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
                anytls_sni = st.text_input("SNI", "www.bing.com", help="TLS握手时的服务器名称指示；onekey 默认伪装为 www.bing.com。")
                anytls_fp = st.selectbox("客户端指纹", ["chrome", "firefox", "safari", "edge", "ios", "android", "random", "none"], index=0, help="TLS客户端指纹")
            with col4:
                anytls_skip_cert_verify = st.checkbox("跳过证书验证", value=True, key=f"anytls_skip_cert_verify_{node_type}", help="是否跳过TLS证书验证")
                anytls_alpn = st.selectbox("ALPN", ["h2,http/1.1", "h2", "http/1.1", "none"], index=0, help="应用层协议协商标识")
                anytls_ip_version = st.selectbox("IP Version", ["默认", "dual", "ipv4", "ipv4-prefer", "ipv6", "ipv6-prefer"], index=0, help="使用的IP协议版本，默认不设置")
        
            anytls_idle_session_check_interval = st.number_input("idle-session-check-interval", value=30, help="空闲会话检查间隔（秒）")
            anytls_idle_session_timeout = st.number_input("idle-session-timeout", value=180, help="空闲会话超时时间（秒）")
            anytls_min_idle_session = st.number_input("min-idle-session", value=2, help="最小空闲会话数")
            with st.expander("ECH 设置", expanded=False):
                anytls_ech_enabled = st.checkbox("启用 ECH", value=False, key=f"anytls_ech_enabled_{node_type}", help="写入 mihomo 官方 ech-opts.enable。")
                anytls_ech_config = st.text_area("ECH config", "", height=80, key=f"anytls_ech_config_{node_type}", help="可留空；留空时由 mihomo 通过 DNS HTTPS/SVCB 记录获取 ECH 配置。")
                anytls_ech_query_server_name = st.text_input("ECH query-server-name", "", key=f"anytls_ech_query_server_name_{node_type}", help="可选；指定通过 DNS 查询 ECH 配置时使用的域名。")
    
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
                manual_node["obfs"] = hy2_obfs_type
                manual_node["obfs-password"] = hy2_obfs_password
            manual_node["up"] = f"{hy2_up_mbps} Mbps"
            manual_node["down"] = f"{hy2_down_mbps} Mbps"
            try:
                manual_node["hop-interval"] = normalize_hy2_hop_interval(hy2_hop_interval)
            except ValueError as exc:
                st.warning(str(exc))
                manual_node["hop-interval"] = 30
            if hy2_fingerprint != "none":
                manual_node["client-fingerprint"] = hy2_fingerprint
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
                ws_opts = {"path": vless_ws_path}
                if vless_ws_host:
                    ws_opts["headers"] = {"Host": vless_ws_host}
                manual_node["ws-opts"] = ws_opts
            elif vless_network == "grpc":
                 manual_node["grpc-opts"] = {"grpc-service-name": vless_grpc_service_name}

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
            if anytls_ech_enabled:
                manual_node["ech-opts"] = {"enable": True}
                if anytls_ech_config.strip():
                    manual_node["ech-opts"]["config"] = anytls_ech_config.strip()
                if anytls_ech_query_server_name.strip():
                    manual_node["ech-opts"]["query-server-name"] = anytls_ech_query_server_name.strip()

        if common_ip_version != "默认" and "ip-version" not in manual_node:
            manual_node["ip-version"] = common_ip_version
        if enable_smux:
            manual_node["smux"] = {
                "enabled": smux_enabled,
                "protocol": smux_protocol,
                "max-connections": smux_max_connections,
            }
            if smux_brutal_enabled:
                manual_node["smux"]["brutal-opts"] = {
                    "enabled": True,
                    "up": f"{smux_brutal_up} Mbps",
                    "down": f"{smux_brutal_down} Mbps",
                }

        # 添加链式代理配置
        if use_dialer_proxy and dialer_proxy_name:
            manual_node["dialer-proxy"] = dialer_proxy_name

        manual_node_yaml = yaml.dump([manual_node], allow_unicode=True, sort_keys=False)
        if st.session_state.get("manual_node_yaml_source") != manual_node_yaml:
            st.session_state["manual_node_yaml_editor"] = manual_node_yaml
            st.session_state["manual_node_yaml_source"] = manual_node_yaml

        edited_manual_node_yaml = st.text_area(
            "当前节点 YAML（可手动编辑）",
            key="manual_node_yaml_editor",
            height=320,
            help="这里显示由表单生成的节点 YAML。你可以直接改字段；点击添加前会重新走统一校验，防止无效 YAML 被写入。",
        )

        if st.button("校验并添加节点", key=f"add_manual_node_{node_type}", help="校验当前 YAML 并添加到节点列表"):
            try:
                parsed_nodes, manual_warnings = parse_proxy_yaml(edited_manual_node_yaml)
                if len(parsed_nodes) != 1:
                    st.error("手动添加一次只能包含 1 个节点；如果要批量导入，请使用“智能 YAML 导入”。")
                else:
                    parsed_node = parsed_nodes[0]
                    existing_names = {proxy.get("name") for proxy in st.session_state.proxies_data}
                    if parsed_node["name"] in existing_names:
                        st.warning(f"节点 '{parsed_node['name']}' 已存在，跳过重复添加")
                    else:
                        manual_sources = [
                            source for source in st.session_state.import_sources
                            if source.get("type") == "manual"
                        ]
                        if manual_sources:
                            manual_source = manual_sources[0]
                            parsed_node["_source_id"] = manual_source["id"]
                            parsed_node["_source_name"] = manual_source["name"]
                            parsed_node["_origin_name"] = parsed_node["name"]
                            manual_source["node_count"] = int(manual_source.get("node_count", 0)) + 1
                        else:
                            parsed_node = register_import_source(
                                source_name,
                                "manual",
                                [parsed_node],
                            )[0]
                        st.session_state.proxies_data.append(parsed_node)
                        st.success(f"节点 '{parsed_node['name']}' 已添加。")
                    for warning in manual_warnings:
                        st.warning(warning)
            except Exception as e:
                st.error(f"节点 YAML 校验失败: {e}")


with tab2:
    render_node_management(render_workflow_step)

with tab3:
    render_workflow_step(
        3,
        "设置分流",
        "选择基础规则源并调整预设目标；修改会保存为草稿，检查并发布后才影响线上订阅。",
    )
    
    if not st.session_state.proxies_data:
        st.warning("请先在“快速填入”或“节点管理”标签页添加节点，才能配置分流规则。")
    else:
        # ==========================
        # 1. 准备配置上下文
        # ==========================
        rule_options = ["dustinwin规则", "lhie1规则", "自定义规则"]
        rule_labels = {
            "dustinwin规则": "DustinWin 规则集（推荐，含 AI/Gemini 增强）",
            "lhie1规则": "lhie1 规则集（兼容旧配置）",
            "自定义规则": "基础自定义规则",
        }
        current_rule_type = st.session_state.get("selected_rule_type", DEFAULT_RULE_TYPE)
        if current_rule_type not in rule_options:
            current_rule_type = DEFAULT_RULE_TYPE
        if (
            current_rule_type == "自定义规则"
            and not saved_config.get("final_yaml")
            and not st.session_state.get("rule_type_allow_custom")
        ):
            current_rule_type = DEFAULT_RULE_TYPE
        rule_type = st.selectbox(
            "基础规则源",
            rule_options,
            index=rule_options.index(current_rule_type),
            format_func=lambda value: rule_labels.get(value, value),
            help="只切换规则内容，不改变现有策略组数量。自定义单条规则和自定义规则集仍保持最高优先级。",
        )
        st.session_state.selected_rule_type = rule_type
        if rule_type == "自定义规则":
            st.session_state.rule_type_allow_custom = True
        try:
            preview_config = build_subscription_config(
                st.session_state.proxies_data,
                st.session_state.global_config,
                st.session_state.custom_rules,
                st.session_state.custom_rule_providers,
                rule_type,
            )
            proxy_groups = preview_config.get("proxy-groups", [])
        except Exception as exc:
            preview_config = {}
            proxy_groups = []
            st.error(f"预览配置生成失败：{exc}")

        # ==========================
        # 2. 规则集选择说明
        # ==========================
        if rule_type == "dustinwin规则":
            st.info("默认使用 DustinWin 的 mihomo-ruleset 进行基础分流，规则集由 OpenClash/mihomo 按周自动更新。")
        elif rule_type == "lhie1规则":
            st.info("当前使用 lhie1 规则集，适合兼容旧配置。您可以在下方添加自定义规则或规则集。")
        else:
            st.info("当前只使用基础自定义规则。您可以在下方添加单条规则或规则集。")

        # ==========================
        # 3. 可视化规则编辑
        # ==========================
        st.subheader("可视化规则编辑")
        
        all_targets = collect_rule_targets(proxy_groups, st.session_state.proxies_data)

        if rule_type in {"dustinwin规则", "lhie1规则"}:
            if rule_type == "dustinwin规则":
                provider_targets_key = "dustinwin_provider_targets"
                widget_prefix = "dustinwin_target_"
                expander_title = "DustinWin 预设规则目标"
                reset_label = "恢复 DustinWin 默认策略"
                provider_items = [
                    (name, str(config["target"]))
                    for name, config in DUSTINWIN_PROVIDERS_MAP.items()
                ]
                caption = "这里可以修改 DustinWin 内置规则集默认走哪个策略组或节点。例如把 ai 从 AI Suite 改成某个固定节点。"
            else:
                provider_targets_key = "lhie1_provider_targets"
                widget_prefix = "lhie1_target_"
                expander_title = "lhie1 预设规则目标"
                reset_label = "恢复 lhie1 默认策略"
                provider_items = [
                    (provider_name, default_target)
                    for provider_name, (_, default_target) in LHIE1_PROVIDERS_MAP.items()
                ]
                caption = "这里可以修改 lhie1 内置规则集默认走哪个策略组或节点。例如把 Netflix 改成某个固定节点。"

            with st.expander(expander_title, expanded=False):
                st.caption(caption)
                if st.button(reset_label, key=f"reset_{provider_targets_key}"):
                    st.session_state.global_config[provider_targets_key] = {}
                    for key in list(st.session_state.keys()):
                        if key.startswith(widget_prefix):
                            del st.session_state[key]
                    st.rerun()

                current_overrides = dict(st.session_state.global_config.get(provider_targets_key, {}))
                next_overrides = {}
                col_provider_a, col_provider_b = st.columns(2)
                for idx, (provider_name, default_target) in enumerate(provider_items):
                    safe_provider_name = "".join(ch if ch.isalnum() else "_" for ch in provider_name)
                    options = list(all_targets)
                    current_target = current_overrides.get(provider_name, default_target)
                    if current_target not in options:
                        options.insert(0, current_target)
                    target_index = options.index(current_target)
                    container = col_provider_a if idx % 2 == 0 else col_provider_b
                    with container:
                        selected_target = st.selectbox(
                            provider_name,
                            options,
                            index=target_index,
                            key=f"{widget_prefix}{safe_provider_name}",
                            help=f"默认目标：{default_target}",
                        )
                    if selected_target != default_target:
                        next_overrides[provider_name] = selected_target

                st.session_state.global_config[provider_targets_key] = next_overrides
                if next_overrides:
                    st.info(f"已覆盖 {len(next_overrides)} 条预设规则，当前为待发布草稿。")
        else:
            st.session_state.global_config["dustinwin_provider_targets"] = {}
            st.session_state.global_config["lhie1_provider_targets"] = {}

        try:
            preview_config = build_subscription_config(
                st.session_state.proxies_data,
                st.session_state.global_config,
                st.session_state.custom_rules,
                st.session_state.custom_rule_providers,
                rule_type,
            )
            proxy_groups = preview_config.get("proxy-groups", [])
        except Exception as exc:
            preview_config = {}
            st.error(f"应用预设规则目标后重新生成预览失败：{exc}")
        
        render_single_rule_editor(all_targets)
                        
        st.divider()

        # ==========================
        # 3. 编辑规则集配置 (Rule Providers)
        # ==========================
        st.subheader("规则集")
        st.caption("规则集使用介绍: https://wiki.metacubex.one/config/rule-providers/content/")
        
        with st.expander("➕ 添加新规则集", expanded=False):
            # 配置文件选项移除，默认全部
            rp_name = st.text_input("别名 (请勿重名)", placeholder="Rule-provider - " + str(uuid.uuid4())[:8], key="rp_name")
            
            col_rp1, col_rp2 = st.columns(2)
            with col_rp1:
                rp_type = st.selectbox("规则集类型", ["http", "file"], key="rp_type")
                rp_behavior = st.selectbox("规则类型", ["domain", "ipcidr", "classical"], key="rp_behavior")
            with col_rp2:
                rp_format = st.selectbox("规则格式", ["yaml", "text", "mrs"], key="rp_format")
                rp_interval = st.number_input("规则集更新时间 (秒)", value=86400, key="rp_interval")
            
            rp_path_or_url = ""
            if rp_type == "http":
                rp_url = st.text_input("规则集地址", placeholder="http://...", key="rp_url")
                # 连通性测试按钮
                if rp_url:
                    if st.button("测试链接可用性", key="test_rp_url"):
                         try:
                             safe_url = validate_external_url(rp_url)
                             resp = requests.head(safe_url, timeout=5, allow_redirects=False)
                             if 300 <= resp.status_code < 400:
                                 st.warning("⚠️ 链接返回重定向，出于安全原因已拒绝自动跟随")
                                 st.stop()
                             if resp.status_code == 200:
                                 st.success("✅ 链接可用")
                             else:
                                 st.warning(f"⚠️ 链接返回状态码: {resp.status_code}")
                         except Exception as e:
                             st.error(f"❌ 连接失败: {e}")
                
            elif rp_type == "file":
                uploaded_file = st.file_uploader("上传规则文件", type=["yaml", "yml", "txt", "list", "mrs"], key="rp_file_upload")
                if uploaded_file:
                    if not rp_name:
                        st.warning("请先填写规则集别名，再上传文件。")
                    else:
                        try:
                            file_path = safe_ruleset_file_path(rp_name, rp_format)
                            file_path.parent.mkdir(parents=True, exist_ok=True)
                            file_path.write_bytes(uploaded_file.getbuffer())
                            safe_filename = file_path.name
                            st.success(f"已保存到: {file_path}")
                        except Exception as exc:
                            safe_filename = ""
                            st.error(f"规则文件保存失败: {exc}")
            
            rp_order = st.selectbox("规则集匹配顺序", ["优先 (覆盖)", "默认 (追加)"], key="rp_order")
            
            # 获取所有策略组名称用于下拉菜单
            rp_target = st.selectbox("指定策略组或节点", all_targets, key="rp_target")
            
            if st.button("保存规则集配置", key="save_rp"):
                if not rp_name:
                    st.error("请输入规则集别名")
                elif not SAFE_RULESET_NAME_PATTERN.fullmatch(rp_name.strip()):
                    st.error("规则集别名只能使用字母、数字、点、下划线或短横线")
                elif rp_name in st.session_state.custom_rule_providers:
                    st.error("该别名已存在")
                elif rp_type == "http" and not rp_url:
                    st.error("请输入规则集 URL")
                elif rp_type == "file" and not uploaded_file:
                     st.error("请上传规则文件")
                else:
                    safe_rp_name = validate_ruleset_alias(rp_name)
                    provider_config = {
                        "type": rp_type,
                        "behavior": rp_behavior,
                        "interval": rp_interval,
                        "format": rp_format,
                        "target": rp_target,
                        "order": rp_order
                    }
                    
                    if rp_type == "http":
                        provider_config["url"] = validate_external_url(rp_url)
                        provider_config["path"] = f"./ruleset/{safe_rp_name}.{rp_format}"
                    elif rp_type == "file":
                         file_path = safe_ruleset_file_path(safe_rp_name, rp_format)
                         if not file_path.is_file():
                             file_path.parent.mkdir(parents=True, exist_ok=True)
                             file_path.write_bytes(uploaded_file.getbuffer())
                         provider_config["path"] = f"./ruleset/{file_path.name}"

                    st.session_state.custom_rule_providers[safe_rp_name] = provider_config
                    st.success(f"规则集 {safe_rp_name} 已添加")
                    st.rerun()
        
        render_rule_provider_list()

with tab4:
    render_workflow_step(
        4,
        "检查与发布",
        "先生成并校验草稿，确认差异后再发布；线上订阅在发布前保持不变。",
    )

    if not st.session_state.proxies_data:
        uploaded_yaml = st.file_uploader(
            "上传本工具生成的旧配置并恢复节点",
            type=["yaml", "yml"],
            help="仅恢复 proxies 节点列表，恢复后先进入草稿，不会直接覆盖线上订阅。",
        )
        if uploaded_yaml:
            if uploaded_yaml.size > MAX_REMOTE_SUBSCRIPTION_BYTES:
                st.error("文件大小超过 5MB，请上传较小的配置文件。")
            else:
                try:
                    restored_config = yaml.safe_load(uploaded_yaml.getvalue().decode("utf-8"))
                    restored_proxies = (
                        restored_config.get("proxies")
                        if isinstance(restored_config, dict)
                        else None
                    )
                    if not isinstance(restored_proxies, list) or not restored_proxies:
                        raise ValueError("配置中没有可恢复的 proxies 列表")
                    tagged_proxies = register_import_source(
                        "旧配置恢复",
                        "restore",
                        restored_proxies,
                    )
                    st.session_state.proxies_data = tagged_proxies
                    st.session_state.draft_restore_notice = len(tagged_proxies)
                    st.rerun()
                except Exception as exc:
                    st.error(f"恢复失败：{exc}")

    restored_count = st.session_state.pop("draft_restore_notice", None)
    if restored_count:
        st.success(f"已恢复 {restored_count} 个节点到草稿。")

    check_notice = st.session_state.pop("draft_check_notice", None)
    if check_notice:
        st.success(check_notice)

    publish_notice = st.session_state.pop("draft_publish_notice", None)
    if publish_notice:
        st.success(publish_notice)

    selected_rule = st.session_state.get("selected_rule_type", DEFAULT_RULE_TYPE)
    draft_signature = current_draft_signature()
    try:
        draft_config = build_subscription_config(
            st.session_state.proxies_data,
            st.session_state.global_config,
            st.session_state.custom_rules,
            st.session_state.custom_rule_providers,
            selected_rule,
        ) if st.session_state.proxies_data else {}
        draft_yaml = build_subscription_yaml(draft_config) if draft_config else ""
        draft_build_error = ""
    except Exception as exc:
        draft_config = {}
        draft_yaml = ""
        draft_build_error = str(exc)

    try:
        published_config = yaml.safe_load(saved_config.get("final_yaml") or "") or {}
    except Exception:
        published_config = {}

    draft_stats = config_summary(draft_config)
    published_stats = config_summary(published_config)
    has_unpublished_changes = draft_yaml != (saved_config.get("final_yaml") or "")

    published_at = saved_config.get("published_at") or saved_config.get("validated_at") or "尚未发布"
    render_publish_summary(has_unpublished_changes, str(published_at), draft_stats, published_stats)

    if draft_build_error:
        st.error(f"草稿生成失败：{draft_build_error}")

    check_column, publish_column = st.columns(2)
    with check_column:
        check_clicked = st.button(
            "检查草稿",
            type="primary",
            use_container_width=True,
            disabled=not bool(st.session_state.proxies_data) or bool(draft_build_error),
        )
    checked_is_current = (
        st.session_state.get("checked_draft_signature") == draft_signature
        and bool(st.session_state.get("checked_draft_yaml"))
    )
    with publish_column:
        publish_clicked = st.button(
            "发布订阅",
            use_container_width=True,
            disabled=not checked_is_current,
            help="当前草稿必须先通过结构检查和 mihomo 内核校验。",
        )

    if check_clicked:
        check_errors, check_warnings = validate_subscription_config(draft_config)
        if check_errors:
            st.session_state.pop("checked_draft_signature", None)
            st.session_state.pop("checked_draft_yaml", None)
            persist_current_draft("failed", "；".join(check_errors))
            st.error(f"结构检查发现 {len(check_errors)} 个错误")
            for error in check_errors:
                st.code(error, language="text")
        else:
            mihomo_result = validate_with_mihomo(draft_yaml)
            if not mihomo_result.ok:
                st.session_state.pop("checked_draft_signature", None)
                st.session_state.pop("checked_draft_yaml", None)
                persist_current_draft(mihomo_result.status, mihomo_result.message)
                st.error(f"mihomo 内核校验失败：{mihomo_result.status}")
                st.code(mihomo_result.message, language="text")
            else:
                st.session_state.checked_draft_signature = draft_signature
                st.session_state.checked_draft_yaml = draft_yaml
                st.session_state.checked_draft_warnings = check_warnings
                st.session_state.checked_draft_validation_status = mihomo_result.status
                st.session_state.checked_draft_validation_message = mihomo_result.message
                persist_current_draft(mihomo_result.status, mihomo_result.message)
                st.session_state.draft_check_notice = "草稿已通过结构检查和 mihomo 内核校验，可以发布。"
                st.rerun()

    if publish_clicked:
        published_token = saved_config["token"]
        save_user_config(
            current_user["id"],
            st.session_state.proxies_data,
            st.session_state.global_config,
            st.session_state.custom_rules,
            st.session_state.custom_rule_providers,
            selected_rule,
            st.session_state.checked_draft_yaml,
            validation_status=st.session_state.get(
                "checked_draft_validation_status",
                "passed",
            ),
            validation_message=st.session_state.get(
                "checked_draft_validation_message",
                "草稿通过结构检查和 mihomo 内核校验后发布",
            ),
            import_sources=st.session_state.import_sources,
        )
        st.session_state.persisted_draft_signature = draft_signature
        st.session_state.pop("checked_draft_signature", None)
        st.session_state.pop("checked_draft_yaml", None)
        st.session_state.pop("checked_draft_warnings", None)
        st.session_state.pop("checked_draft_validation_status", None)
        st.session_state.pop("checked_draft_validation_message", None)
        st.session_state.draft_publish_notice = (
            f"订阅已发布：{get_public_base_url()}/sub/{published_token}"
        )
        st.rerun()

    checked_yaml = st.session_state.get("checked_draft_yaml")
    if checked_yaml and st.session_state.get("checked_draft_signature") == draft_signature:
        warnings = st.session_state.get("checked_draft_warnings") or []
        if warnings:
            with st.expander(f"校验警告（{len(warnings)}）", expanded=False):
                for warning in warnings:
                    st.warning(warning)
        preview_tab, diff_tab = st.tabs(["草稿 YAML", "发布差异"])
        with preview_tab:
            st.text_area("配置预览", value=checked_yaml, height=560, disabled=True)
            st.download_button(
                "下载草稿 config.yaml",
                data=checked_yaml,
                file_name="config.yaml",
                mime="application/x-yaml",
                use_container_width=True,
            )
        with diff_tab:
            for label, key in PUBLISH_DIFF_LABELS:
                delta = draft_stats[key] - published_stats[key]
                st.write(f"{label}：已发布 {published_stats[key]} → 草稿 {draft_stats[key]}（{delta:+d}）")
            published_node_names = set(extract_proxy_names(published_config))
            draft_node_names = set(extract_proxy_names(draft_config))
            added_nodes = sorted(draft_node_names - published_node_names)
            removed_nodes = sorted(published_node_names - draft_node_names)
            if added_nodes:
                st.markdown(f"**新增节点（{len(added_nodes)}）**")
                st.code("\n".join(added_nodes), language="text")
            if removed_nodes:
                st.markdown(f"**移除节点（{len(removed_nodes)}）**")
                st.code("\n".join(removed_nodes), language="text")
            if not added_nodes and not removed_nodes:
                st.caption("节点名称集合无变化；差异可能来自节点字段、全局选项或分流规则。")

current_signature = current_draft_signature()
if current_signature != st.session_state.get("persisted_draft_signature"):
    st.session_state.pop("checked_draft_signature", None)
    st.session_state.pop("checked_draft_yaml", None)
    st.session_state.pop("checked_draft_warnings", None)
    st.session_state.pop("checked_draft_validation_status", None)
    st.session_state.pop("checked_draft_validation_message", None)
    persist_current_draft()


st.markdown(
    f"""
<footer class="ccg-footer" aria-label="产品与服务信息">
  <div class="ccg-footer-brand"><span class="ccg-footer-signal" aria-hidden="true"></span>Clash Config Gen <span>· 已登录会话</span></div>
  <div class="ccg-footer-meta"><span>Docker · mihomo 内核校验</span><span>配置草稿与已发布订阅分离</span></div>
  <nav class="ccg-footer-links" aria-label="帮助链接"><a href="{PROJECT_REPOSITORY_URL}" target="_blank" rel="noopener noreferrer">项目文档</a><a href="{MIHOMO_DOCUMENTATION_URL}" target="_blank" rel="noopener noreferrer">Mihomo 帮助</a><span>© 2026</span></nav>
</footer>
""",
    unsafe_allow_html=True,
)
