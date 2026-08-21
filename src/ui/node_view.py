import html
from hashlib import sha256
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components
import yaml

from importers import parse_proxy_yaml


NODE_DRAG_COMPONENT = components.declare_component(
    "ccg_node_drag_handle",
    path=str(Path(__file__).parents[1] / "components" / "node_drag_handle"),
)


def _parse_single_node_yaml(updated_yaml: str) -> dict:
    """Parse one edited node through the shared importer contract.

    The editor accepts the same YAML/list/config shapes as the import flow, but
    deliberately requires exactly one resulting node before the caller mutates
    ``st.session_state.proxies_data``.
    """
    parsed_nodes, _warnings = parse_proxy_yaml(updated_yaml)
    if len(parsed_nodes) != 1:
        raise ValueError("手动编辑一次只能保存 1 个节点")
    return parsed_nodes[0]


def _merge_internal_metadata(updated_proxy: dict, original_proxy: dict) -> dict:
    """Keep storage-only source metadata out of the editor but in the result."""
    merged = dict(updated_proxy)
    merged.update({key: value for key, value in original_proxy.items() if str(key).startswith("_")})
    return merged


def render_node_management(render_workflow_step) -> None:
    render_workflow_step(
        2,
        "整理节点",
        "集中查看、筛选、排序和修正已导入节点，后续策略组会自动引用这里的节点。",
    )
    proxies = st.session_state.proxies_data
    if not proxies:
        st.info("暂无节点。请先在“导入节点”中批量导入或手动添加。")
        return

    total_nodes = len(proxies)
    protocol_names = sorted({str(proxy.get("type", "unknown")) for proxy in proxies})
    duplicate_names = total_nodes - len({proxy.get("name") for proxy in proxies})
    metric_total, metric_protocols, metric_duplicates = st.columns(3)
    metric_total.metric("节点总数", total_nodes)
    metric_protocols.metric("协议类型", len(protocol_names))
    metric_duplicates.metric("重复名称", duplicate_names)

    filter_search, filter_protocol = st.columns([2, 1])
    with filter_search:
        node_search = st.text_input(
            "搜索节点",
            placeholder="名称、服务器或协议",
            key="node_management_search",
        ).strip().lower()
    with filter_protocol:
        selected_protocol = st.selectbox(
            "协议筛选",
            ["全部"] + protocol_names,
            key="node_management_protocol",
        )

    visible_proxies = []
    for original_idx, proxy in enumerate(proxies):
        searchable = " ".join(str(proxy.get(field, "")) for field in ("name", "server", "type", "port")).lower()
        if node_search and node_search not in searchable:
            continue
        if selected_protocol != "全部" and proxy.get("type") != selected_protocol:
            continue
        visible_proxies.append((original_idx, proxy))

    st.caption(f"当前显示 {len(visible_proxies)} / {total_nodes} 个节点")
    for idx, proxy in visible_proxies:
        _render_node_card(idx, proxy)


def _render_node_card(idx: int, proxy: dict) -> None:
    server_label = f"{proxy.get('server', '-')}:{proxy.get('port', '-')}"
    node_key = sha256(f"{proxy.get('_source_id', '')}:{proxy.get('name', '')}".encode("utf-8")).hexdigest()[:10]
    with st.container(border=True):
        st.markdown('<div class="node-card-anchor" aria-hidden="true"></div>', unsafe_allow_html=True)
        col_drag, col_summary, col_edit, col_delete = st.columns([0.34, 3.7, 0.72, 0.72])
        with col_drag:
            reorder_event = NODE_DRAG_COMPONENT(
                index=idx,
                name=str(proxy.get("name") or "未命名节点"),
                key=f"node_drag_{node_key}_{idx}",
            )
            _apply_reorder(reorder_event)
        with col_summary:
            st.markdown(
                f'<div class="node-card-summary"><strong>{html.escape(str(proxy.get("name") or "未命名节点"))}</strong><span><b>{html.escape(str(proxy.get("type") or "unknown"))}</b>{html.escape(server_label)}</span></div>',
                unsafe_allow_html=True,
            )
        with col_edit:
            if st.button("编辑", key=f"edit_proxy_{idx}", use_container_width=True):
                st.session_state.editing_proxy_idx = idx
                st.session_state.editing_proxy_data = proxy.copy()
                public_proxy = {key: value for key, value in proxy.items() if not str(key).startswith("_")}
                st.session_state[f"edit_proxy_yaml_{idx}"] = yaml.dump(
                    [public_proxy], default_flow_style=False, allow_unicode=True, sort_keys=False
                )
                st.rerun()
        with col_delete:
            if st.button("移除", key=f"delete_proxy_{idx}", use_container_width=True):
                st.session_state.proxies_data.pop(idx)
                if st.session_state.get("editing_proxy_idx") == idx:
                    _clear_editor()
                st.rerun()

        if st.session_state.get("editing_proxy_idx") == idx:
            _render_inline_editor(idx, proxy)


def _apply_reorder(reorder_event) -> None:
    if not isinstance(reorder_event, dict):
        return
    nonce = str(reorder_event.get("nonce") or "")
    source_idx = reorder_event.get("source_index")
    target_idx = reorder_event.get("target_index")
    proxies = st.session_state.proxies_data
    if not (
        nonce
        and nonce != st.session_state.get("last_node_reorder_nonce")
        and isinstance(source_idx, int)
        and isinstance(target_idx, int)
        and 0 <= source_idx < len(proxies)
        and 0 <= target_idx < len(proxies)
        and source_idx != target_idx
    ):
        return
    moved_proxy = proxies.pop(source_idx)
    proxies.insert(target_idx, moved_proxy)
    st.session_state.last_node_reorder_nonce = nonce
    _clear_editor()
    st.rerun()


def _render_inline_editor(idx: int, proxy: dict) -> None:
    editing_data = st.session_state.get("editing_proxy_data", proxy)
    st.markdown(
        f'<div class="node-inline-editor-title">正在编辑 <strong>{html.escape(str(editing_data.get("name") or "未命名节点"))}</strong></div>',
        unsafe_allow_html=True,
    )
    updated_yaml = st.text_area(
        "节点配置 YAML",
        key=f"edit_proxy_yaml_{idx}",
        height=280,
        help="保存前会校验 name、type、server 和 port，并保留内部兼容元数据。",
    )
    save_col, cancel_col, _ = st.columns([1, 1, 3])
    with save_col:
        if st.button("保存修改", key=f"save_proxy_{idx}", type="primary", use_container_width=True):
            try:
                updated_proxy = _parse_single_node_yaml(updated_yaml)
                updated_proxy = _merge_internal_metadata(updated_proxy, editing_data)
                st.session_state.proxies_data[idx] = updated_proxy
                _clear_editor()
                st.success("节点信息已更新")
                st.rerun()
            except Exception as exc:
                st.error(f"YAML 解析错误：{exc}")
    with cancel_col:
        if st.button("取消", key=f"cancel_proxy_{idx}", use_container_width=True):
            _clear_editor()
            st.rerun()


def _clear_editor() -> None:
    st.session_state.pop("editing_proxy_idx", None)
    st.session_state.pop("editing_proxy_data", None)
