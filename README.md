# Clash-Config-Gen

面向 OpenClash / Clash Meta 的配置与订阅生成器，适合自建节点用户把 `onekey.sh` 输出的 OpenClash YAML、手动节点和自定义规则统一管理成一个真实可拉取的订阅链接。

当前版本已经支持用户注册、登录、SQLite 持久化、管理员初始化、Docker 部署和真实订阅接口。

## 解决的问题

- 不再只在浏览器会话里临时生成配置，容器重启后用户、节点、规则和订阅 Token 都会保留。
- 不再返回占位订阅接口，`/sub/{token}` 会输出真实 YAML，可直接填入 OpenClash。
- 支持导入 `onekey.sh` 打印的 OpenClash YAML 节点片段，也保留手动添加节点。
- 管理员账号通过 Docker 环境变量创建，普通用户可以开放注册。

## Docker 部署

推荐直接使用 Docker Compose。你可以自行反代 Web UI 和 API，本项目默认按你的域名生成订阅链接。

### 方式一：生产环境使用 GHCR 镜像

这是推荐部署方式。GitHub Actions 会把镜像发布到 GitHub Container Registry，服务器只负责拉取镜像并运行。

1. 准备环境变量：

```bash
cp .env.example .env
nano .env
```

`.env` 至少需要修改管理员密码：

```env
PUBLIC_BASE_URL=https://clash.910501.xyz
ALLOW_REGISTRATION=true
ADMIN_USERNAME=admin
ADMIN_PASSWORD=请改成强密码
WEB_PORT=8501
API_PORT=8000
```

2. 启动服务：

```bash
docker compose -f docker-compose.prod.yml up -d
```

3. 后续更新：

```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

生产版 Compose：

```yaml
services:
  clash-gen:
    image: ghcr.io/10000ge10000/clash-config-gen:main
    container_name: clash-gen
    restart: always
    ports:
      - "8501:8501"
      - "8000:8000"
    environment:
      - PUBLIC_BASE_URL=https://clash.910501.xyz
      - APP_DB_PATH=/app/data/app.db
      - ALLOW_REGISTRATION=true
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=change-this-admin-password
    volumes:
      - ./data:/app/data
      - ./ruleset:/app/ruleset
```

### 方式二：服务器本地构建

如果你不想使用 GHCR 镜像，也可以直接在服务器克隆仓库后本地构建：

```bash
docker compose up -d
```

环境变量说明：

| 变量 | 说明 |
| --- | --- |
| `PUBLIC_BASE_URL` | 对外访问域名，用于生成订阅链接，例如 `https://clash.910501.xyz` |
| `APP_DB_PATH` | SQLite 数据库路径，Docker 中建议保持 `/app/data/app.db` |
| `ALLOW_REGISTRATION` | 是否允许网页公开注册，`true` 或 `false` |
| `ADMIN_USERNAME` | 容器启动时自动初始化的管理员用户名 |
| `ADMIN_PASSWORD` | 容器启动时自动初始化的管理员密码，生产环境必须修改 |

## GitHub Actions 镜像发布

项目已内置 `.github/workflows/docker-publish.yml`，支持：

- 推送到 `main` 分支时自动构建并发布 `main`、`latest`、`sha-*` 标签。
- 推送 `v*` 标签时发布对应版本镜像。
- 在 GitHub Actions 页面手动执行 `Docker Build and Publish`。

镜像地址：

```text
ghcr.io/10000ge10000/clash-config-gen:main
```

如果仓库是私有仓库，服务器拉取镜像前需要登录 GHCR：

```bash
echo YOUR_GITHUB_TOKEN | docker login ghcr.io -u 10000ge10000 --password-stdin
```

如果仓库或镜像包是公开的，通常可以直接拉取。

## 不推荐的部署方式

- **Vercel**：当前项目依赖 Streamlit 长驻进程、FastAPI 长驻接口和 SQLite 本地持久化。Vercel Functions 是 Serverless 模型，文件系统不可作为 SQLite 持久化存储；除非把 UI 改成 Next.js，并把数据库换成外部 Postgres/KV，否则不适合直接部署。
- **GitHub Pages**：只能托管静态页面，不能运行 Python、Streamlit、FastAPI、用户注册登录或动态订阅接口。

## 反代建议

如果你想让 `https://clash.910501.xyz/` 访问 Web UI，同时让 `https://clash.910501.xyz/sub/{token}` 拉取订阅，需要在反代中把路径分流：

- `/sub/` 和 `/health` 转发到容器 `8000`。
- 其他路径转发到容器 `8501`。

订阅地址格式：

```text
https://clash.910501.xyz/sub/用户自己的随机Token
```

用户登录后，侧边栏会直接显示完整订阅链接。

## 使用流程

1. 启动 Docker 服务。
2. 使用 `ADMIN_USERNAME` / `ADMIN_PASSWORD` 登录管理员账号。
3. 普通用户可以自行注册，管理员可以在侧边栏禁用用户或重置 Token。
4. 在“快速填入”中选择 `OpenClash/onekey YAML`。
5. 粘贴 `onekey.sh` 输出的 OpenClash YAML 片段，或粘贴完整 `config.yaml`。
6. 点击导入节点。
7. 按需调整手动节点、分流规则和全局配置。
8. 在“生成与检查”中点击生成，配置会保存到数据库，订阅立即生效。

## 支持的 onekey 协议字段

| 协议 | 关键字段 |
| --- | --- |
| VLESS Reality | `uuid`、`tls`、`flow`、`servername`、`reality-opts`、`client-fingerprint`、`smux` |
| TUIC v5 | `uuid`、`password`、`sni`、`alpn`、`udp-relay-mode`、`congestion-controller` |
| Shadowsocks 2022 | `cipher`、`password`、`udp` |
| AnyTLS | `password`、`sni`、`alpn`、`client-fingerprint`、`skip-cert-verify` |
| VMess WebSocket | `uuid`、`alterId`、`cipher`、`network: ws`、`ws-opts.path` |
| Hysteria2 | `password`、`sni`、`alpn`、`ports`、`hop-interval` |

## 本地开发

Windows PowerShell：

```powershell
.\.venv\Scripts\Activate.ps1
$env:PUBLIC_BASE_URL="https://clash.910501.xyz"
$env:ADMIN_USERNAME="admin"
$env:ADMIN_PASSWORD="change-this-admin-password"
streamlit run src\web_app.py
```

另开一个终端启动订阅 API：

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn api:app --app-dir src --host 0.0.0.0 --port 8000
```

健康检查：

```bash
curl http://localhost:8000/health
```

订阅检查：

```bash
curl http://localhost:8000/sub/你的Token
```
