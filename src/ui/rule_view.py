import streamlit as st


def collect_rule_targets(proxy_groups: list[dict], proxies: list[dict]) -> list[str]:
    groups = [group["name"] for group in proxy_groups if group.get("name")]
    proxies_names = [proxy.get("name") for proxy in proxies if proxy.get("name")]
    return sorted(set(groups + proxies_names + ["DIRECT", "REJECT", "REJECT-DROP", "Proxy"]))


def render_single_rule_editor(all_targets: list[str]) -> None:
    with st.expander(f"单条规则（{len(st.session_state.custom_rules)}）", expanded=False):
        col_type, col_target = st.columns(2)
        with col_type:
            st.write("**规则类型**")
            rule_type = st.selectbox(
                "选择规则类型",
                ["DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD", "IP-CIDR", "GEOIP", "MATCH"],
                key="rule_type_select_v3",
            )
        with col_target:
            st.write("**目标策略**")
            mode = st.selectbox(
                "选择目标策略组模式",
                ["从列表中选择", "手动输入名称"],
                label_visibility="collapsed",
                key="group_mode_select",
            )
            target = (
                st.selectbox("选择目标策略或节点", all_targets, key="target_group_select_v3")
                if mode == "从列表中选择"
                else st.text_input("输入策略组名称", placeholder="例如: MyGroup", key="custom_group_input_v3")
            )

        value = ""
        if rule_type != "MATCH":
            value = st.text_input(
                "输入值 (域名/IP/国家代码)",
                placeholder="例如: google.com",
                key="rule_value_input_v3",
            )
        if st.button("➕ 添加规则", key="add_rule_v3"):
            if not target:
                st.error("请选择或输入目标策略组")
            elif rule_type != "MATCH" and not value:
                st.error("请输入规则值")
            else:
                rule = f"{rule_type},{value},{target}" if rule_type != "MATCH" else f"MATCH,{target}"
                if rule in st.session_state.custom_rules:
                    st.warning("该规则已存在")
                else:
                    st.session_state.custom_rules.append(rule)
                    st.success(f"规则已添加: {rule}")
                    st.rerun()

        for index, rule in enumerate(st.session_state.custom_rules):
            col_rule, col_action = st.columns([4, 1])
            col_rule.text(f"{index + 1}. {rule}")
            with col_action:
                if st.button("删除", key=f"delete_custom_rule_{index}", help="删除此规则"):
                    st.session_state.custom_rules.pop(index)
                    st.rerun()


def render_rule_provider_list() -> None:
    st.subheader("已添加规则")
    providers = st.session_state.custom_rule_providers
    if not providers:
        return
    st.write(f"**已添加的规则集列表 ({len(providers)})**")
    for name, config in list(providers.items()):
        with st.expander(f"{name} ({config.get('target', '未指定')})", expanded=False):
            st.json(config)
            if st.button(f"删除 {name}", key=f"del_rp_{name}"):
                del providers[name]
                st.rerun()
