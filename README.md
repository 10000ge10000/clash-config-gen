# Clash-Config-Gen

`Clash-Config-Gen` 是一个面向 OpenClash / Clash Meta 的订阅配置生成器。它的核心目标很直接：把自建节点、`onekey.sh` 输出的 OpenClash YAML、手动补充节点和常用分流规则统一管理起来，最终生成一个可以被 OpenClash 真实拉取的订阅链接。

项目当前已经支持用户注册、登录、SQLite 持久化、管理员初始化、Docker 部署、GHCR 镜像发布和动态订阅接口。配置不再只存在浏览器会话里，容器重启后用户、节点、规则和订阅 Token 都会保留。

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

## 一键部署

在服务器中新建一个目录，例如 `clash-config-gen`，然后创建 `docker-compose.yml`：

```yaml
services:
  clash-gen:
    image: ghcr.io/10000ge10000/clash-config-gen:main
    container_name: clash-gen
    restart: always
    ports:
      # Web 管理页面端口。反代 Web UI 时指向这个端口。
      - "8501:8501"
      # 订阅 API 端口。反代 /sub/ 和 /health 时指向这个端口。
      - "8000:8000"
    environment:
      # 改成你的公网访问地址。订阅链接会基于这个地址生成。
      - PUBLIC_BASE_URL=https://clash.910501.xyz
      # 是否允许普通用户自行注册。只给自己用可以改成 false。
      - ALLOW_REGISTRATION=true
      # 初始化管理员账号。首次启动时自动创建。
      - ADMIN_USERNAME=admin
      # 必须改成强密码，不要使用示例值。
      - ADMIN_PASSWORD=please-change-this-password
      # SQLite 数据库存储位置，保持默认即可。
      - APP_DB_PATH=/app/data/app.db
    volumes:
      # 保存用户、节点、订阅 Token 和最终配置。不要删除这个目录。
      - ./data:/app/data
      # 保存自定义规则集文件。暂时不用也可以保留。
      - ./ruleset:/app/ruleset
```

启动：

```bash
docker compose up -d
```

更新：

```bash
docker compose pull
docker compose up -d
```

部署后访问 Web 管理页面，使用 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD` 登录。生成配置后，侧边栏会显示当前用户的订阅链接，格式如下：

```text
https://clash.910501.xyz/sub/用户自己的随机Token
```

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

如果订阅客户端或 CDN 对无扩展名路径兼容性不好，也可以使用等价的 YAML 路径：

```text
https://clash.910501.xyz/sub/用户自己的随机Token/config.yaml
```

诊断接口只返回非敏感统计，适合排查 OpenClash 是否拉到可用配置：

```text
https://clash.910501.xyz/sub/用户自己的随机Token/diagnostics
```

## Nginx反向代理配置

部署后需要配置 Nginx 反向代理，将订阅 API 和 Web UI 分别转发到不同端口。**这是最常见的部署问题**：如果配置错误，订阅链接会返回 HTML 页面而非 YAML 配置。

### 关键说明

本服务包含两个独立的 Web 服务：
- **Streamlit Web UI**：端口 8501，用于管理界面
- **FastAPI 订阅 API**：端口 8000，用于 `/sub/` 和 `/health` 接口

Nginx 必须将 `/sub/` 和 `/health` 路径转发到 FastAPI 端口（8000），其他路径转发到 Streamlit 端口（8501）。

### Nginx 配置示例

```nginx
server {
    listen 443 ssl;
    server_name clash.910501.xyz;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Streamlit Web UI (端口 8501)
    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Streamlit WebSocket 支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # FastAPI 订阅 API (端口 8000) - 必须单独配置！
    location /sub/ {
        proxy_pass http://127.0.0.1:8000/sub/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # FastAPI 健康检查
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
    }
}
```

### 常见问题

| 问题 | 原因 | 解决方案 |
| --- | --- | --- |
| 订阅链接返回 HTML 页面 | `/sub/` 被转发到 8501 | 确保 `/sub/` 转发到 8000 端口 |
| OpenClash 无法拉取订阅 | 反代配置错误 | 检查 Nginx 日志，确认 `/sub/` 返回 `application/x-yaml` |
| 普通脚本测试返回 403 / Cloudflare 1010 | CDN 浏览器完整性检查拦截了默认脚本 User-Agent | 用 OpenClash、mihomo、浏览器或显式设置 User-Agent 测试；真实 OpenClash 拉取应返回 `application/x-yaml` |
| 客户端只看到内置 Global | 订阅内容不是有效 YAML，或 YAML 缺少 `proxy-groups` | 重新在“生成与检查”中保存；新版本会拒绝继续提供没有策略组的坏配置 |
| OpenClash 报 mihomo 字段错误 | 节点字段不符合 mihomo 规范 | 生成器会先规范化节点，再调用 mihomo 内核校验；校验失败不会保存订阅 |
| Web UI 无法正常交互 | WebSocket 未配置 | 添加 WebSocket 升级头（见上方示例） |

## mihomo 内核校验

Docker 镜像内置 `mihomo v1.19.24`。点击“生成并检查配置文件”时，系统会先生成 YAML，再执行真实 mihomo 配置测试；只有测试通过才会写入数据库并对外发布订阅。

本地开发如果暂时没有安装 mihomo，可以显式关闭内核校验：

```bash
MIHOMO_VALIDATE_ENABLED=false streamlit run src/web_app.py
```

生产环境不建议关闭该选项，否则 OpenClash 只能在导入后才暴露配置错误。

如果修改了 docker-compose.yml 中的端口映射（例如将 8000 映射到 8502），需要同步修改 Nginx 配置中的 `proxy_pass` 地址。

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
docker compose pull
docker compose up -d
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

docker-compose.yml           # 本仓库开发/自建部署模板
.github/workflows/           # GitHub Actions 构建发布流程
```

## 安全注意

- 生产环境必须修改 `ADMIN_PASSWORD`。
- `data/` 目录包含 SQLite 数据库，不要提交到 Git。
- `.env` 包含管理员密码，不要提交到 Git。
- `.vscode/` 属于本地编辑器配置，不纳入版本库。
