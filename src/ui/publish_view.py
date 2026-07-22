import html

import streamlit as st

PUBLISH_DIFF_LABELS = (("节点", "nodes"), ("策略组", "groups"), ("规则集", "providers"), ("规则", "rules"))


def render_publish_summary(
    has_unpublished_changes: bool,
    published_at: str,
    draft_stats: dict[str, int],
    published_stats: dict[str, int],
) -> None:
    """集中渲染草稿/线上状态和差异指标，不参与构建、检查或发布业务逻辑。"""
    status_class = "draft-status-pending" if has_unpublished_changes else "draft-status-clean"
    status_text = "有待发布修改" if has_unpublished_changes else "草稿与线上一致"
    st.markdown(
        f"""
        <div class="draft-status {status_class}">
          <div><strong>{status_text}</strong><span>已发布：{html.escape(str(published_at))}</span></div>
          <span>草稿会自动保存，但只有点击发布才会更新订阅链接内容。</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    for column, (label, key) in zip(st.columns(4), PUBLISH_DIFF_LABELS):
        delta = draft_stats[key] - published_stats[key]
        column.metric(label, draft_stats[key], delta=delta if delta else None)
