import html
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
              <h1><span>把复杂配置变成</span><span>可控的发布流程</span></h1>
              <p>导入节点、检查规则、生成订阅。每一步都可追踪，每一次发布都有明确差异。</p>
              <div class="auth-flow" aria-label="配置工作流">
                <article class="auth-flow-item"><span class="auth-flow-icon" aria-hidden="true"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M4 7h16M4 12h10M4 17h16"/></svg></span><strong>节点导入</strong><span>统一解析多种配置来源</span></article>
                <article class="auth-flow-item"><span class="auth-flow-icon" aria-hidden="true"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="m5 12 4 4L19 6"/></svg></span><strong>规则检查</strong><span>先验证草稿，再确认差异</span></article>
                <article class="auth-flow-item"><span class="auth-flow-icon" aria-hidden="true"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M12 3v18m9-9H3"/></svg></span><strong>安全发布</strong><span>将已检查的配置发布为订阅</span></article>
              </div>
            </section>
            <section class="auth-card">
              <h2>{title}</h2><div class="auth-card-subtitle">{subtitle}</div>
              <nav class="auth-tabs"><a class="auth-tab {login_class}" href="/">登录</a><a class="auth-tab {register_class}" href="/?auth=register">注册</a></nav>
              {error_html}{form_html}
              <div class="auth-security">TLS 加密传输 · HttpOnly 会话 · 可随时撤销</div>
            </section>
            <footer class="auth-footer"><span>Docker · mihomo 内核校验</span><span class="auth-footer-links"><a href="{project_url}" target="_blank" rel="noopener noreferrer">项目文档</a><a href="{documentation_url}" target="_blank" rel="noopener noreferrer">Mihomo 帮助</a><span>会话使用 HttpOnly Cookie 管理</span></span></footer>
          </main>
        </div>
        """
    )
    st.markdown(page_html, unsafe_allow_html=True)
