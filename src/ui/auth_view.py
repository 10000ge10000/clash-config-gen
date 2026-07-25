import html
import os
from textwrap import dedent

import streamlit as st

from auth import get_bool_env
from security import create_csrf_token


def render_auth_gate(brand_mark_svg: str, project_url: str, documentation_url: str) -> None:
    """渲染登录/注册门禁；认证校验继续由 FastAPI 完成。"""
    register_mode = st.query_params.get("auth") == "register"
    registration_enabled = get_bool_env("ALLOW_REGISTRATION", False)
    error_message = html.escape(st.query_params.get("auth_error", ""))
    title = "创建新账号" if register_mode else "欢迎回来"
    subtitle = "建立你的专属配置空间" if register_mode else "登录以继续管理节点与订阅"
    csrf_token = html.escape(create_csrf_token("auth"), quote=True)
    mihomo_version = html.escape(os.getenv("MIHOMO_VERSION", "v1.19.29"))

    if register_mode and registration_enabled:
        form_html = dedent(
            f"""
            <form class="auth-form" method="post" action="/sub/auth/register">
              <input name="csrf_token" type="hidden" value="{csrf_token}">
              <label class="auth-field">用户名
                <input name="username" autocomplete="username" required minlength="3" maxlength="32" placeholder="3-32 位字母、数字、点或短横线">
              </label>
              <label class="auth-field">密码
                <input name="password" type="password" autocomplete="new-password" required minlength="8" placeholder="至少 8 位">
              </label>
              <label class="auth-field">确认密码
                <input name="password_confirm" type="password" autocomplete="new-password" required minlength="8" placeholder="再次输入密码">
              </label>
              <div class="auth-warp-notice">
                注册将自动申请独立 WARP MASQUE 配置并立即发布到你的订阅。
                继续注册即表示你已了解
                <a href="https://www.cloudflare.com/application/terms/" target="_blank" rel="noopener noreferrer">Cloudflare 服务条款</a>。
              </div>
              <button class="auth-submit" type="submit">注册并进入控制台</button>
            </form>
            """
        ).strip()
    elif register_mode:
        form_html = '<div class="auth-registration-closed">当前部署已关闭公开注册，请联系管理员创建账号。</div>'
    else:
        form_html = dedent(
            f"""
            <form class="auth-form" method="post" action="/sub/auth/login">
              <input name="csrf_token" type="hidden" value="{csrf_token}">
              <label class="auth-field">用户名
                <input name="username" autocomplete="username" required placeholder="请输入用户名">
              </label>
              <label class="auth-field">密码
                <input name="password" type="password" autocomplete="current-password" required placeholder="请输入密码">
              </label>
              <div class="auth-options"><label class="auth-remember"><input name="remember" type="checkbox"><span>保持登录 30 天</span></label></div>
              <button class="auth-submit" type="submit">安全登录</button>
            </form>
            """
        ).strip()

    error_html = f'<div class="auth-error">{error_message}</div>' if error_message else ""
    register_class = "active" if register_mode else ""
    login_class = "" if register_mode else "active"
    page_html = dedent(
        f"""
        <div class="auth-page">
          <div class="auth-signal-field" aria-hidden="true">
            <span class="auth-signal-line auth-signal-line-a"></span><span class="auth-signal-line auth-signal-line-b"></span>
            <span class="auth-signal-node auth-signal-node-a"></span><span class="auth-signal-node auth-signal-node-b"></span><span class="auth-signal-node auth-signal-node-c"></span>
          </div>
          <main class="auth-layout">
            <header class="auth-brand"><div class="auth-brand-mark">{brand_mark_svg}</div><div><div class="auth-brand-name">CLASH CONFIG GEN</div><div class="auth-brand-desc">Secure configuration intelligence</div></div></header>
            <section class="auth-intro">
              <div class="auth-eyebrow">CONFIGURATION INTELLIGENCE</div>
              <h1><span>一份订阅覆盖</span><span>主流 Mihomo 客户端</span></h1>
              <p>协议、内核和客户端兼容范围公开透明；配置发布前使用真实 Mihomo 内核检查。</p>
              <div class="auth-flow auth-capabilities" aria-label="兼容能力">
                <article class="auth-flow-item auth-capability-card">
                  <div class="auth-capability-heading"><span class="auth-flow-icon" aria-hidden="true"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M4 7h16M4 12h10M4 17h16"/></svg></span><div><strong>协议</strong><span>可视化录入与 YAML 预制</span></div></div>
                  <div class="auth-capability-label">可视化录入</div>
                  <div class="auth-chip-list"><span>Shadowsocks</span><span>VMess</span><span>VLESS</span><span>Trojan</span><span>AnyTLS</span><span>Hysteria2</span><span>TUIC</span></div>
                  <div class="auth-capability-label">YAML / 系统预制</div>
                  <div class="auth-chip-list"><span>WireGuard</span><span>MASQUE h3-l4proxy</span></div>
                </article>
                <article class="auth-flow-item auth-capability-card">
                  <div class="auth-capability-heading"><span class="auth-flow-icon" aria-hidden="true"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="m5 12 4 4L19 6"/></svg></span><div><strong>内核</strong><span>构建与发布双重验证</span></div></div>
                  <div class="auth-kernel-status"><i></i><span>Mihomo Meta {mihomo_version}</span></div>
                  <div class="auth-chip-list auth-chip-list-wide"><span>真实内核校验</span><span>AMD64</span><span>ARM64</span></div>
                </article>
                <article class="auth-flow-item auth-capability-card">
                  <div class="auth-capability-heading"><span class="auth-flow-icon" aria-hidden="true"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M12 3v18m9-9H3"/></svg></span><div><strong>客户端</strong><span>Mihomo 配置生态</span></div></div>
                  <div class="auth-client-list"><span>OpenClash</span><span>Nikki</span><span>Clash Verge Rev</span><span>FlClash</span><span>其他 Mihomo 兼容客户端</span></div>
                </article>
              </div>
            </section>
            <section class="auth-card">
              <h2>{title}</h2><div class="auth-card-subtitle">{subtitle}</div>
              <nav class="auth-tabs"><a class="auth-tab {login_class}" href="/">登录</a><a class="auth-tab {register_class}" href="/?auth=register">注册</a></nav>
              {error_html}{form_html}
              <div class="auth-security">TLS 加密传输 · HttpOnly 会话 · 可随时撤销</div>
            </section>
            <footer class="auth-footer"><span>Docker · Mihomo Meta {mihomo_version} · AMD64 / ARM64</span><span class="auth-footer-links"><a href="{project_url}" target="_blank" rel="noopener noreferrer">项目文档</a><a href="{documentation_url}" target="_blank" rel="noopener noreferrer">Mihomo 帮助</a><span>会话使用 HttpOnly Cookie 管理</span></span></footer>
          </main>
        </div>
        """
    )
    st.markdown(page_html, unsafe_allow_html=True)
