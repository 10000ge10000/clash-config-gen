# Clash Config Gen 设计系统

> **V2 · 生产主页 · 以 `design/` 下实际实现为准**
>
> 本文档记录当前线上 V2 主页的真实设计令牌与约定。令牌取自 `design/assets/app.css`，结构取自 `design/index.html`；文档与代码不一致时以代码为准，并应回头修正文档。早期 Streamlit 时代的五工作区与 Manrope / Space Grotesk 方案已废弃。

## 产品定位

- **产品**：Clash / OpenClash / mihomo 多用户订阅配置生成与发布工作台。
- **核心用户任务**：导入节点 → 整理节点 → 配置规则与全局 → 校验并发布订阅。
- **设计目标**：让用户始终清楚当前草稿、校验结果和发布状态；界面只展示真实数据，不伪造节点数量、延迟或运行指标。

## 文件结构

```text
design/
├── index.html        # 只含 HTML 结构，无内联 <script>、无内联事件属性
└── assets/
    ├── app.css       # 全部样式与设计令牌
    └── app.js        # 全部前端逻辑（单个 IIFE，由 defer 加载）
```

- 由 FastAPI 提供：`/` 与 `/v2` 返回 `index.html`，`/ui/app.css`、`/ui/app.js` 返回 `assets/` 下对应文件。
- CSP 为 `script-src 'self' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline'`：新增脚本只能放进 `app.js`，不得写内联 `<script>` 或 `onclick=` 之类属性；内联 `style="..."` 允许，但优先使用 class。
- 调试开关：`window.__CCG_DEBUG__`（测试通过 `page.addInitScript` 注入）或 localStorage 的 `ccg-debug=1`，由 `app.js` 读取。
- `tests/v2-ui-regression.spec.mjs` 会断言响应头 CSP 含 `script-src 'self'`、页面无 CSP 违规、无内联脚本与事件属性。

## 色彩令牌

默认浅色主题定义在 `:root`，暗色主题由 `html.dark` 覆盖同名变量，选择保存在 localStorage 的 `v2-theme`。

| 变量 | 浅色 | 暗色 | 用途 |
| --- | --- | --- | --- |
| `--bg` | `#f2f6fb` | `#070b14` | 页面背景 |
| `--bg-2` | `#e9eef6` | `#0b1120` | 次级背景 |
| `--text` | `#16233c` | `#e6edf7` | 正文 |
| `--text-dim` | `#4e5e79` | `#8b98ad` | 次要文字 |
| `--text-faint` | `#5d6a80` | `#7d8aa0` | 辅助说明、元数据 |
| `--accent` | `#0891b2` | `#22d3ee` | 主强调（青） |
| `--accent-2` | `#4f46e5` | `#6366f1` | 渐变中段（靛） |
| `--accent-3` | `#7c3aed` | `#a78bfa` | 渐变末段（紫） |
| `--success` | `#059669` | `#34d399` | 成功 |
| `--warn` | `#d97706` | `#fbbf24` | 警告 |
| `--danger` | `#dc2626` | `#f87171` | 失败、删除 |
| `--grad-main` | 青 → 靛 → 紫 135° | 同色相提亮 | 主操作、品牌标记 |

此外还有按用途拆出的派生变量：`--card`、`--border`、`--panel-bg`、`--input-bg`、`--code-bg`、`--accent-text`、`--on-accent` 以及 YAML 高亮的 `--y-*` 等，新增组件应优先复用，不直接写色值。

### `--text-faint` 对比度结论

- 浅色 `#5d6a80`：对 `--bg` 5.04:1，对 `--bg-2` 4.70:1，对卡片合成色 `#fbfcfe` 5.33:1。
- 暗色 `#7d8aa0`：对 `--bg` 5.64:1，对 `--bg-2` 5.39:1，对卡片悬停合成色 5.14:1，对 `--bg-2` 上的卡片 4.83:1。
- 以上均不低于 WCAG AA 的 4.5:1。更浅（浅色）或更暗（暗色）的取值会在 `--bg-2` 或卡片上掉到 4.5 以下，不要再调低对比。修改任一底色变量时需重新核算。
- 状态必须同时用文字、图标或形状表达，不能只靠颜色。

## 渐变与玻璃拟态的使用边界

早期版本禁止紫色渐变与玻璃拟态；V2 实际采用了它们，边界如下。

- 渐变 `--grad-main` 只用于主操作按钮、品牌标记、标题强调词和当前步骤指示；不用于大面积背景或正文区块。
- 玻璃拟态（半透明 `--card` / `--panel-bg` 加 `backdrop-filter: blur(...)`）用于顶栏、卡片、面板、浮层；承载表单输入和代码的区域使用 `--input-bg`、`--code-bg` 这类更实的底色，保证可读性。
- 背景网格、光晕（`.glow-orb`）和扫描线（`.scanline`）对比度低于内容层，不承载信息，且在 `prefers-reduced-motion` 下停止动画。
- 不使用霓虹描边或夸张阴影；阴影只表示层级（`--shadow-card`、`--toast-shadow`）。

## 字体、间距与形状

- 正文：`Inter, SF Pro Display, Segoe UI, PingFang SC, Microsoft YaHei, system-ui, sans-serif`（`--font`）。
- 技术标识、数字、YAML：`JetBrains Mono, Cascadia Code, SF Mono, Consolas, monospace`（`--mono`）。
- 不依赖外部字体服务，未安装的字体回落到系统字体。
- 字号：统计数字 27px，正文与表单 12–14px，技术辅助文字 10.5–12px。
- 圆角：基础 `--radius` 14px，输入与小控件 9–12px。
- 侧栏宽度 `--sidebar-w` 300px；动效缓动 `--ease-out`。

## 布局结构

- **顶栏 + 侧栏 + 主区**：侧栏放四步导航与品牌，主区一次显示一个步骤面板。
- **四步导航**：`#step-tab-1..4`，`role="tab"`，当前项 `aria-selected="true"` 且 `tabindex="0"`，其余 `tabindex="-1"`，支持方向键切换；对应面板 `#step1..#step4`。
  1. 导入节点：YAML、订阅链接、分享链接三种导入方式（`.method-card`）。
  2. 节点管理：节点卡片网格、搜索、节点表单与原始 YAML 编辑。
  3. 规则与全局：预设规则、自定义规则、规则集、全局开关。
  4. 校验与发布：检查清单、YAML 预览、订阅链接、发布。
- **节点卡片**（`.node-card`）：名称、服务器、协议、状态；左侧拖动把手排序，并提供 `Alt + ↑/↓` 键盘替代；编辑表单在卡片内展开，不使用页面底部的独立编辑区。
- **登录层**（`#loginOverlay`）：`role="dialog"`、`aria-modal="true"`，内含登录/注册两个标签页与表单，每个输入框都有可见 `<label>`；未登录时覆盖整个工作台，登录成功后移除 `active`。
- 订阅状态、统计与发布差异只展示服务端返回的真实数据。

## 组件规则

- 按钮：主要操作用 `--grad-main`、`--on-accent` 文字；次要操作为透明或半透明底加 `--border` 边框；disabled 降低对比并禁用交互。
- 输入：可见 label、`--input-bg` 底、`--border` 边框，聚焦时边框变为强调色；错误信息贴近字段并说明恢复方式。
- 提示（toast）、确认和空状态都使用文字说明，不只靠颜色。
- 主题切换在顶栏，选择写入 localStorage；读写必须 try/catch，存储不可用时回落到浅色。

## 可访问性约定

- **焦点框**：键盘焦点使用 `outline: 3px solid var(--accent)`，`outline-offset: 2px`，用 `:focus-visible` 触发，不得用 `outline: none` 后不补替代样式。
- **减少动效**：`@media (prefers-reduced-motion: reduce)` 将动画与过渡压缩到 0.01ms 并关闭背景动画；新增动效必须在该规则覆盖范围内。
- **触控目标**：目标规范为可点击控件至少 44×44px。当前实现尚未全部达标（部分紧凑控件如节点搜索框、规则删除按钮小于此值），新增或改动的控件应按 44px 设计，存量控件逐步调整，不在文档里声称已完成。
- 标签页使用 `role="tablist"` / `role="tab"` / `aria-selected`；对话框用 `aria-modal` 与 `aria-labelledby`。
- 文本对比度不低于 WCAG AA（见上文 `--text-faint` 结论）。
- 375px 视口下不得出现页面横向滚动，由 Playwright 用例覆盖。

## 响应式断点

实际使用的断点为 1180px、1100px、900px、720px 和 390px。

| 宽度 | 规则 |
| --- | --- |
| > 1180px | 完整侧栏与多列工作台 |
| 901–1180px | 保留侧栏，规则区和部分网格改为单列（1100px） |
| <= 900px | 导入方式卡片单列 |
| <= 720px | 窄屏布局：表单单列、控件收紧 |
| <= 390px | 进一步收紧间距；保持无横向滚动 |

## Streamlit 回滚 UI

`src/web_app.py`（8501 端口）保留为回滚入口，沿用 Streamlit 原生组件，不再随 V2 的设计令牌演进。仅在 V2 不可用时使用，样式修改限于修复可读性与对比度问题。

## 不变功能契约

- 前端改动不得改变 FastAPI 的公开路由、JSON 字段、认证 Cookie、订阅 Token、SQLite 数据结构、规则集文件、mihomo 检查或发布逻辑。
- 保留复制订阅链接、Token 重置、管理员用户管理、全局设置、导入、节点编辑、规则配置、草稿检查和发布流程。
- 不插入测试账号、密码、虚构指标或假数据。
