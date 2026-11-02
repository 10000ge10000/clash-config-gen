# Clash-Config-Gen

[![Blog](https://img.shields.io/badge/Blog-910501.xyz-orange)](https://blog.910501.xyz/)
[![Bilibili](https://img.shields.io/badge/B%E7%AB%99-59438380-00a1d6?logo=bilibili)](https://space.bilibili.com/59438380)
[![YouTube](https://img.shields.io/badge/YouTube-10000%20AI%20Share-ff0000?logo=youtube&logoColor=white)](https://www.youtube.com/channel/UCqgvZnCN9-9pZcL4SWxmnDw)

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
| 增强分流 | 默认使用 DustinWin `mihomo-ruleset`，补全 AI、流媒体、国内外域名与 IP 规则 |
| 规则自动更新 | OpenClash/mihomo 按订阅中的 `rule-providers.interval` 每周更新，服务端也会缓存一份规则集 |
| Docker 部署 | 使用 GHCR 镜像和 Docker Compose 运行，数据通过 volume 持久化 |
| 自动构建 | 推送到 `main` 后由 GitHub Actions 自动构建并发布镜像 |

## 兼容范围

- **协议**：可视化录入 Shadowsocks、VMess、VLESS、Trojan、AnyTLS、Hysteria2、TUIC；YAML 导入支持 WireGuard。项目明确拒绝 `type: masque` 节点。
- **内核**：镜像固定 Mihomo Meta `v1.19.33`，配置发布前执行真实 `mihomo -t`；镜像支持 AMD64、ARM64。
- **客户端**：OpenClash、Nikki、Clash Verge Rev、FlClash，以及其他支持对应 Mihomo 配置格式的客户端。

## 一键部署

在服务器中新建一个目录，例如 `clash-config-gen`，先生成仅保存在本机的 CSRF 密钥，再创建 `.env` 和 `docker-compose.yml`。密钥至少需要 32 个字符；下面的命令会生成 64 个十六进制字符：

```bash
mkdir -p clash-config-gen
cd clash-config-gen
umask 077
cat > .env <<ENVEOF
PUBLIC_BASE_URL=https://sub.example.com
CSRF_SECRET=$(openssl rand -hex 32)
# 可选：留空则不创建管理员
ADMIN_PASSWORD=
ENVEOF
chmod 600 .env
```

`.env` 只用于当前服务器，不要提交到 Git，也不要在多套部署之间复用。

必填变量：

- `PUBLIC_BASE_URL`：对外访问地址，订阅链接基于它生成；未设置时应用拒绝启动。
- `CSRF_SECRET`：至少 32 个随机字符；不能使用 `.env.example` 里的占位值，否则应用启动失败（进程直接退出）。

可选变量：`ADMIN_USERNAME` / `ADMIN_PASSWORD`（留空则不创建管理员，见下文）、`ALLOW_REGISTRATION`、`TRUSTED_PROXY_CIDRS`、`MIHOMO_HOME`、`MIHOMO_FIRST_RUN_TIMEOUT`、注册频率限制 `REGISTER_RATE_LIMIT_PER_WINDOW` / `REGISTER_RATE_LIMIT_WINDOW_SECONDS`、远程抓取总耗时上限 `EXTERNAL_FETCH_DEADLINE_SECONDS` 等，完整列表见 `.env.example`。

然后创建 `docker-compose.yml`：

```yaml
services:
  clash-gen:
    # 生产建议把 main 换成 sha-<提交短哈希>，避免浮动标签带来不可控升级
    image: ghcr.io/10000ge10000/clash-config-gen:main
    container_name: clash-gen
    restart: always
    stop_grace_period: 20s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    ports:
      # 两个端口都只绑本机，公网入口统一由 Nginx/OpenResty 反代。
      # 8501 为 Streamlit 回滚入口，8000 为 FastAPI 主入口。
      - "127.0.0.1:8501:8501"
      - "127.0.0.1:8000:8000"
    environment:
      - PUBLIC_BASE_URL=${PUBLIC_BASE_URL:?请在 .env 中设置 PUBLIC_BASE_URL}
      - CSRF_SECRET=${CSRF_SECRET:?请在 .env 中设置 CSRF_SECRET}
      # 是否允许普通用户自行注册。公网部署建议保持 false。
      - ALLOW_REGISTRATION=false
      # HTTPS 部署保持 true；仅本地 HTTP 调试时临时设为 false。
      - AUTH_COOKIE_SECURE=true
      # 可信反代网段，详见下文“可信代理与客户端 IP”。
      - TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128,172.16.0.0/12
      # 初始化管理员账号；ADMIN_PASSWORD 留空则不创建。
      - ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD:-}
      - APP_DB_PATH=/app/data/app.db
      - RULESET_CACHE_ENABLED=true
      - RULESET_UPDATE_INTERVAL=604800
      - RULESET_CACHE_DIR=/app/ruleset/dustinwin
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

容器以非 root 用户（`app`，uid 10001）运行：入口脚本先以 root 修正 `/app/data`、`/app/ruleset` 的归属，再用 `setpriv` 降权，所以宿主机上属 root 的挂载目录无需手动改权限。

### 数据库备份与宿主机操作

SQLite 已启用 WAL 模式，容器内进程以 uid 10001 运行，`data/` 下除 `app.db` 外还会出现 `app.db-wal`、`app.db-shm`：

- 备份不要只拷贝 `app.db`，WAL 中尚未合并的数据会丢失。请使用 `sqlite3 app.db ".backup '/path/backup.db'"` 或 Python `sqlite3` 的 backup API（`deploy/oracle-1` 上的 `backup-db.sh` 用的就是 backup API，是安全的）。
- 在宿主机上直接操作数据库，请用 `docker exec clash-gen ...` 或以 uid 10001 身份执行（如 `sudo -u '#10001' sqlite3 ...`），避免以 root 打开后生成属 root 的 `-wal` / `-shm` 文件，导致容器内进程之后只读失败。
- 入口脚本无法修正数据目录归属时会直接退出容器（而不是带着只读数据库继续运行），请按日志提示检查挂载目录权限。

### 可信代理与客户端 IP

应用只信任来自 `TRUSTED_PROXY_CIDRS` 内地址的 `X-Forwarded-For`，用于登录限流和日志。默认值只含本机回环地址。端口绑定到 `127.0.0.1` 后，经 Docker 端口映射进入容器的连接，对端地址是 docker bridge 网关（如 `172.24.0.1`），不在默认范围内，因此上面的示例追加了 `172.16.0.0/12`。该范围只在端口仅绑本机、反代与容器同机时可以放行；如果端口对外暴露，不要信任这个网段。

应用会从右往左跳过 `X-Forwarded-For` 中属于可信网段的地址，取第一个不可信地址作为客户端 IP，左侧可能被伪造的条目不予采用。站点套了 Cloudflare 而反代没有还原真实 IP 时，最右侧是 Cloudflare 边缘地址，需要把 [Cloudflare 官方网段](https://www.cloudflare.com/ips/) 也加进 `TRUSTED_PROXY_CIDRS`，`deploy/oracle-1/docker-compose.yml` 就是这样配置的。

`ADMIN_PASSWORD` 为可选项：留空时不会创建管理员账号（已有数据库里的账号不受影响）；设置后首次启动会创建 `ADMIN_USERNAME` 对应账号。如果该用户名已被普通用户占用，不会自动提权；管理员已存在时也不会用它覆盖密码。创建完成后可以从 `.env` 中移除。部署后访问 Web 管理页面，使用该账号登录。勾选“保持登录 30 天”后，浏览器会保存 `HttpOnly` 会话 Cookie，服务端仅保存令牌摘要；退出登录或禁用用户会立即撤销对应会话。

生成配置后，侧边栏会显示当前用户的订阅链接，格式如下：

```text
https://clash.910501.xyz/sub/用户自己的随机Token
```

## 使用流程

1. 启动 Docker 服务。
2. 使用 `.env` 中的管理员账号登录。
3. 开启公开注册后，新账号会以“待配置”状态创建；管理员可在侧边栏禁用用户或重置订阅 Token。
4. 在“快速填入”中选择 `OpenClash/onekey YAML`。
5. 粘贴 `onekey.sh` 输出的 OpenClash YAML 片段，或粘贴完整 `config.yaml`。
6. 点击“导入节点”，节点会进入当前用户的配置列表。
7. 按需调整手动节点、分流规则和全局配置。分流默认使用 DustinWin 规则集，也可以切回 lhie1 兼容规则。
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

部署后需要配置 Nginx（或 OpenResty）反向代理，将公网入口统一转发到 FastAPI。**这是最常见的部署问题**：如果配置错误，订阅链接会返回 HTML 页面而非 YAML 配置。

### 关键说明

本服务包含两个独立的 Web 服务：
- **FastAPI V2**：端口 8000，负责公网根页面、`/api/`、`/v2`、`/sub/`、`/ruleset/` 和 `/health`
- **Streamlit 回滚后端**：端口 8501，仅保留为本机直连的快速回滚入口；生产反代不公开转发到 8501

生产反代必须将根路径和下列所有路径转发到 FastAPI 端口（8000）。8501 建议只监听 `127.0.0.1`，需要回滚时再把公网根路径临时切回 8501，并同时保留 Streamlit 所需的 WebSocket 头；不要把未配置的 Streamlit 页面误当作 V2 API。

### Nginx 配置示例

```nginx
server {
    listen 443 ssl;
    server_name clash.910501.xyz;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # V2 根页面（FastAPI 端口 8000）
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # FastAPI JSON API（端口 8000）
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # FastAPI 订阅 API（端口 8000）
    location /sub/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # 规则集缓存接口（端口 8000）
    location /ruleset/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # 精确健康检查，避免被其它前缀规则截获
    location = /health {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
    }

    # V2 页面（FastAPI 端口 8000）
    location = /v2 {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
    }
    location /v2/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
    }
}
```

Streamlit 回滚后端不需要额外的公网 location。确认它只绑定本机后，可在服务器上直接访问 `http://127.0.0.1:8501`；若必须临时切换公网根入口，应恢复带 WebSocket 升级头的 Streamlit 反代，并在回滚完成后再次执行 OpenResty 配置检查。

### 常见问题

| 问题 | 原因 | 解决方案 |
| --- | --- | --- |
| 订阅链接返回 HTML 页面 | `/sub/` 被转发到 8501 | 确保 `/sub/` 转发到 8000 端口 |
| 规则集链接返回 HTML 页面 | `/ruleset/` 被转发到 8501 | 确保 `/ruleset/` 转发到 8000 端口 |
| 规则集链接返回 503 | 服务端缓存尚未下载完成 | 等待后台更新完成，或检查容器网络能否访问 GitHub Release |
| OpenClash 无法拉取订阅 | 反代配置错误 | 检查 Nginx 日志，确认 `/sub/` 返回 `application/x-yaml` |
| 普通脚本测试返回 403 / Cloudflare 1010 | CDN 浏览器完整性检查拦截了默认脚本 User-Agent | 用 OpenClash、mihomo、浏览器或显式设置 User-Agent 测试；真实 OpenClash 拉取应返回 `application/x-yaml` |
| 客户端只看到内置 Global | 订阅内容不是有效 YAML，或 YAML 缺少 `proxy-groups` | 重新在“生成与检查”中保存；新版本会拒绝继续提供没有策略组的坏配置 |
| OpenClash 报 mihomo 字段错误 | 节点字段不符合 mihomo 规范 | 生成器会先规范化节点，再调用 mihomo 内核校验；校验失败不会保存订阅 |
| Streamlit 回滚入口无法正常交互 | 回滚反代未保留 WebSocket 升级头 | 切回 8501 时恢复 Streamlit 的 WebSocket 配置；V2 FastAPI 根页面不依赖该连接 |
| **双 UI 并发编辑** | **整草稿最后写入覆盖** | **同一份草稿的多个浏览器标签/窗口会最后写入获胜**（与现有 Streamlit UI 行为一致）；README 已注明，避免多标签页冲突 |

## mihomo 内核校验

Docker 镜像内置 `mihomo v1.19.33`。点击“生成并检查配置文件”时，系统会先生成 YAML，再执行真实 mihomo 配置测试；只有测试通过才会写入数据库并对外发布订阅。Dockerfile 对 AMD64 和 ARM64 官方发布包分别执行固定 SHA256 校验。

本地开发如果暂时没有安装 mihomo，可以显式关闭内核校验：

```bash
MIHOMO_VALIDATE_ENABLED=false streamlit run src/web_app.py
```

生产环境不建议关闭该选项，否则 OpenClash 只能在导入后才暴露配置错误。

新账号在首次发布有效节点前，订阅接口返回 HTTP 409。导入、手动保存和发布配置都会拒绝大小写不敏感的 `type: masque` 节点。

如果修改了 docker-compose.yml 中的端口映射（例如将 8000 映射到 8502），需要同步修改 Nginx 配置中的 `proxy_pass` 地址，并继续保持 `127.0.0.1` 绑定。

## 分流规则与自动更新

项目默认使用 [DustinWin/ruleset_geodata](https://github.com/DustinWin/ruleset_geodata) 的 `mihomo-ruleset` 规则集增强分流，并为 Google 保留独立策略组。例如：

| DustinWin 规则集 | 默认目标策略 |
| --- | --- |
| `ai.mrs` | `AI Suite` |
| `google.list`、`google-cn.mrs` | `Google` |
| `youtube.mrs` | `Youtube` |
| `netflix.mrs`、`netflixip.mrs` | `Netflix` |
| `disney.mrs` | `Disney Plus` |
| `max.mrs` | `HBO Max` |
| `spotify.mrs` | `Spotify` |
| `bilibili.mrs` | `Bilibili` |
| `media.mrs`、`mediaip.mrs` | `Global TV` |
| `cn.mrs`、`cnip.mrs` | `Domestic` |
| `telegramip.mrs` | `Telegram` |
| `ads.mrs` | `AdBlock` |
| `gfw.mrs`、`proxy.mrs`、`tld-proxy.mrs` | `Proxy` |

Google 使用独立的 `Google` 策略组；YouTube 规则优先匹配 `Youtube` 策略组，不会被通用 Google 规则覆盖。

自动更新分两层：

- 客户端更新：订阅 YAML 会写入 `rule-providers.interval: 604800`，OpenClash/mihomo 每 7 天自动更新规则集。
- 服务端缓存：容器启动后会在后台下载规则集到 `ruleset/dustinwin/`，并按 `RULESET_UPDATE_INTERVAL` 周期刷新。

生成订阅时默认优先引用本服务缓存地址：

```text
https://你的域名/ruleset/dustinwin/ai.mrs
```

如果缓存文件尚未下载完成，该接口会返回 `503`，不会生成空文件。已有缓存不会因为后续下载失败被覆盖。

相关环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `RULESET_CACHE_ENABLED` | `true` | 是否启用服务端规则集缓存 |
| `RULESET_UPDATE_INTERVAL` | `604800` | 服务端缓存更新间隔，单位秒 |
| `RULESET_CACHE_DIR` | `/app/ruleset/dustinwin` | 容器内规则集缓存目录 |

如果你不想让订阅引用本服务缓存，可以把 `RULESET_CACHE_ENABLED=false`，订阅会直接引用 DustinWin GitHub Release 地址。

V2 上传的自定义规则集会保存为用户隔离的内容哈希版本，并以带当前订阅 Token 的 HTTP provider 写入订阅 YAML。规则集 URL 只允许对应用户的当前 Token 访问；重置 Token 后旧规则集 URL 和旧订阅立即失效，新订阅会物化为新 URL。草稿移除不会立即删除物理版本，发布成功后才会按“当前草稿引用 + 已发布 YAML 引用”安全清理旧版本；旧草稿中的 `./ruleset/<alias>.<ext>` 全局兼容路径保持可读且不会被迁移。

## onekey 协议兼容

在 VPS 上运行 `x export`，把输出粘贴到“快速填入”的 YAML 导入即可，一次导入全部节点。输出首行带 `# onekey-export` 标记，此时默认勾选“覆盖同名节点”，同一台 VPS 重置凭据后重新导入会就地更新，节点顺序和策略组引用不变。节点名是 `<节点标识>-<协议>`，多台 VPS 不会冲突。

| 协议 | 已适配字段 |
| --- | --- |
| VLESS Reality | `uuid`、`tls`、`flow`、`servername`、`reality-opts`、`client-fingerprint` |
| VLESS XHTTP Reality Enc | `uuid`、`network: xhttp`、`xhttp-opts`、`encryption`、`alpn`、`servername`、`reality-opts`、`client-fingerprint`（客户端内核需 v1.19.22 或更高） |
| TUIC v5 | `uuid`、`password`、`sni`、`alpn`、`udp-relay-mode`、`congestion-controller` |
| Shadowsocks 2022 | `cipher`、`password`、`udp` |
| AnyTLS | `password`、`sni`、`alpn`、`client-fingerprint`、`skip-cert-verify`、`ech-opts` |
| VMess WebSocket | `uuid`、`alterId`、`cipher`、`tls`、`network: ws`、`ws-opts.path`、`ws-opts.headers`、`smux.brutal-opts` |
| Hysteria2 | `password`、`sni`、`alpn`、`ports`、`hop-interval` |

导入时会做基础校验：

- 节点必须包含 `name`、`type`、`server`、`port`。
- 端口必须在 `1-65535` 范围内。
- 重名节点默认跳过；勾选“覆盖同名节点”后就地替换。
- 对部分 OpenClash 内核可能不支持的协议字段只提示警告，不擅自删除。

### TCP Brutal 与多路复用 (smux) 使用指引

- **服务端 TCP Brutal V2（内核全自动加速，推荐）**：
  - **无需 smux 与客户端配置**：TCP Brutal V2 属于纯服务端 Linux 内核级单边拥塞控制算法，服务端部署后对所有入站 TCP 连接自动生效，客户端**无需且不应开启 `smux.brutal-opts`**。
  - **推荐原生多连接协议**：在 TCP Brutal V2 服务端环境下，强烈推荐优先使用原生多连接协议（如 **VLESS Reality**、**Trojan**、**Shadowsocks** 等）。原生多 TCP 连接可由服务端内核 Brutal 独立高效调度发包，既享有极端弱网抗丢包加速，又规避了应用层 smux 多路复用带来的队头阻塞（HOL Blocking）与单连接性能损耗。
- **客户端 smux Brutal 握手（仅限特殊场景）**：
  - 仅限客户端为 Linux 且装有对应 TCP Brutal 内核模块、同时服务端开启了 smux brutal 速率握手协商的极少数场景。普通平台（Windows / macOS / iOS / Android）没有该内核模块，实测（mihomo v1.19.33，macOS 客户端）开启后连接正常，只留一条 debug 日志，Brutal 不生效，开了也没有意义。
  - 因此，本项目已将所有协议表单中 `smux_brutal_enabled` 默认值统一定为 `false`，保障跨平台稳定可用。普通用户保持默认关闭即可。

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
  config_defaults.py  # Web 与配置生成流程共享的 OpenClash 默认配置
  clash_meta_gen.py   # 策略组生成逻辑
  node_builder.py     # **新增** 节点构建逻辑（build_manual_node + NODE_FORM_SCHEMA），供前端表单渲染 + 后端校验共用单一事实来源

docker-compose.yml           # 开发/自建模板（本地 build，非生产部署文件）
docker-compose.prod.yml      # 使用 GHCR 镜像的部署示例，镜像标签由 IMAGE_TAG 指定
deploy/oracle-1/             # 作者生产环境（Oracle1）的 compose，仅供参考
design/                      # V2 界面静态原型（/v2 路径在线预览）
.github/workflows/           # GitHub Actions 构建发布流程
```

## 安全注意

- `ADMIN_PASSWORD` 不要使用示例值；不需要预置管理员时保持为空。
- 生产环境建议把镜像标签固定为 `sha-<提交短哈希>`（`docker-compose.prod.yml` 通过 `IMAGE_TAG` 指定），确认新版本正常后再升级。
- `data/` 目录包含 SQLite 数据库，不要提交到 Git。
- `.env` 包含管理员密码和 CSRF 密钥，不要提交到 Git。
- `.vscode/` 属于本地编辑器配置，不纳入版本库。
