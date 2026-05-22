# Clash-Config-Gen

`Clash-Config-Gen` 是一个面向 OpenClash / Clash Meta 的订阅配置生成器。它的核心目标很直接：把自建节点、`onekey.sh` 输出的 OpenClash YAML、手动补充节点和常用分流规则统一管理起来，最终生成一个可以被 OpenClash 真实拉取的订阅链接。

项目当前已经支持用户注册、登录、SQLite 持久化、管理员初始化、Docker 部署、GHCR 镜像发布和动态订阅接口。配置不再只存在浏览器会话里，容器重启后用户、节点、规则和订阅 Token 都会保留。

## 项目架构

```mermaid
flowchart LR
    user[用户浏览器] --> ui[Streamlit Web UI<br/>账号登录 / 节点导入 / 配置生成]
    openclash[OpenClash 客户端] --> sub[FastAPI 订阅接口<br/>/sub/{token}]

    ui --> importer[导入解析器<br/>OpenClash YAML / onekey 片段 / 分享链接]
    ui --> builder[配置生成器<br/>Clash YAML / 策略组 / 规则]
    sub --> db[(SQLite 数据库<br/>用户 / Token / 最终订阅 YAML)]
    ui --> db
    builder --> db

    actions[GitHub Actions] --> image[GHCR 镜像<br/>ghcr.io/10000ge10000/clash-config-gen:main]
    image --> docker[Docker Compose 部署]
    docker --> ui
    docker --> sub
```

## 核心能力

| 能力 | 说明 |
| --- | --- |
| 真实订阅链接 | 每个用户拥有独立 Token，`/sub/{token}` 返回可被 OpenClash 拉取的 YAML |
| 持久化存储 | 使用 SQLite 保存用户、节点、规则、订阅 Token 和最终 YAML |
| 用户系统 | 支持普通用户注册登录，管理员账号由 Docker 环境变量初始化 |
| onekey 适配 | 支持导入 `onekey.sh` 打印的 OpenClash YAML 节点片段 |
| 手动节点 | 保留手动添加 SS、VLESS、VMess、TUIC、AnyTLS、Hysteria2 等节点 |
| Docker 部署 | 使用 GHCR 镜像和 Docker Compose 运行，数据通过 volume 持久化 |
| 自动构建 | 推送到 `main` 后由 GitHub Actions 自动构建并发布镜像 |

## 推荐部署

生产环境推荐直接使用 GitHub Container Registry 镜像：

```text
ghcr.io/10000ge10000/clash-config-gen:main
```

先准备环境变量：

```bash
cp .env.example .env
nano .env
```

`.env` 示例：

```env
PUBLIC_BASE_URL=https://clash.910501.xyz
ALLOW_REGISTRATION=true
ADMIN_USERNAME=admin
ADMIN_PASSWORD=please-change-this-password
WEB_PORT=8501
API_PORT=8000
```

启动服务：

```bash
docker compose -f docker-compose.prod.yml up -d
```

后续更新：

```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

`docker-compose.prod.yml` 会挂载两个目录：

| 路径 | 用途 |
| --- | --- |
| `./data:/app/data` | 保存 SQLite 数据库，包含用户、订阅 Token 和配置 |
| `./ruleset:/app/ruleset` | 保存自定义规则集文件 |

## 环境变量

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `PUBLIC_BASE_URL` | 是 | 对外访问地址，用于生成订阅链接，例如 `https://clash.910501.xyz` |
| `ADMIN_USERNAME` | 是 | 初始化管理员用户名 |
| `ADMIN_PASSWORD` | 是 | 初始化管理员密码，生产环境必须使用强密码 |
| `ALLOW_REGISTRATION` | 否 | 是否开放普通用户注册，默认 `true` |
| `WEB_PORT` | 否 | Streamlit Web UI 映射端口，默认 `8501` |
| `API_PORT` | 否 | FastAPI 订阅接口映射端口，默认 `8000` |

## 使用流程

1. 启动 Docker 服务。
2. 使用 `.env` 中的管理员账号登录。
3. 普通用户可自行注册，管理员可在侧边栏禁用用户或重置订阅 Token。
4. 在“快速填入”中选择 `OpenClash/onekey YAML`。
5. 粘贴 `onekey.sh` 输出的 OpenClash YAML 片段，或粘贴完整 `config.yaml`。
6. 点击“导入节点”，节点会进入当前用户的配置列表。
7. 按需调整手动节点、分流规则和全局配置。
8. 在“生成与检查”中点击生成，配置会保存到数据库，订阅立即生效。
9. 将侧边栏展示的订阅链接填入 OpenClash。

订阅地址格式：

```text
https://clash.910501.xyz/sub/用户自己的随机Token
```

## onekey 协议兼容

| 协议 | 已适配字段 |
| --- | --- |
| VLESS Reality | `uuid`、`tls`、`flow`、`servername`、`reality-opts`、`client-fingerprint`、`smux` |
| TUIC v5 | `uuid`、`password`、`sni`、`alpn`、`udp-relay-mode`、`congestion-controller` |
| Shadowsocks 2022 | `cipher`、`password`、`udp` |
| AnyTLS | `password`、`sni`、`alpn`、`client-fingerprint`、`skip-cert-verify` |
| VMess WebSocket | `uuid`、`alterId`、`cipher`、`network: ws`、`ws-opts.path` |
| Hysteria2 | `password`、`sni`、`alpn`、`ports`、`hop-interval` |

导入时会做基础校验：

- 节点必须包含 `name`、`type`、`server`、`port`。
- 端口必须在 `1-65535` 范围内。
- 重名节点会跳过，避免覆盖已有配置。
- 对部分 OpenClash 内核可能不支持的协议字段只提示警告，不擅自删除。

## GitHub Actions

项目内置 Docker 镜像发布工作流：

```text
.github/workflows/docker-publish.yml
```

触发规则：

| 触发方式 | 行为 |
| --- | --- |
| 推送到 `main` | 构建并发布 `main`、`latest`、`sha-*` 镜像标签 |
| 推送 `v*` 标签 | 构建并发布对应版本镜像 |
| 手动执行 workflow | 手动构建并发布镜像 |

发布完成后，服务器只需要执行：

```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

## 目录说明

```text
src/
  api.py              # FastAPI 订阅接口
  web_app.py          # Streamlit Web UI
  storage.py          # SQLite 持久化
  auth.py             # 用户认证与密码哈希
  importers.py        # YAML / 分享链接导入解析
  config_builder.py   # Clash 配置生成与校验
  clash_meta_gen.py   # 策略组生成逻辑

docker-compose.prod.yml      # 生产部署模板
.env.example                 # 环境变量示例
.github/workflows/           # GitHub Actions 构建发布流程
```

## 安全注意

- 生产环境必须修改 `ADMIN_PASSWORD`。
- `data/` 目录包含 SQLite 数据库，不要提交到 Git。
- `.env` 包含管理员密码，不要提交到 Git。
- `.vscode/` 属于本地编辑器配置，不纳入版本库。
