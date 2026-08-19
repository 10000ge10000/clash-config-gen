# 使用官方 Python Slim 镜像减少体积
FROM python:3.11-slim

ARG MIHOMO_VERSION=v1.19.29
ARG MIHOMO_SHA256_AMD64=60de76a35a6cbf7b4fa4a20f5c257c24345d1d635ab1aa3877022a1997ef413c
ARG MIHOMO_SHA256_ARM64=9a868b5e4e0ad91d9d71e1b41b0cfce78aaba44360c30df74a723f8e3926a86c

# 设置工作目录
WORKDIR /app

# 设置环境变量，防止 Python 生成 pyc 文件，并让 stdout/stderr 直接输出
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV MIHOMO_VERSION=${MIHOMO_VERSION}

# 复制依赖文件并安装 (利用 Docker 缓存层)
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 安装 dos2unix、curl 和证书；curl 用于健康检查和下载固定版本 mihomo
RUN apt-get update && apt-get install -y dos2unix curl ca-certificates gzip && rm -rf /var/lib/apt/lists/*

# 安装 mihomo，用真实内核校验生成出来的订阅配置。
# 这里按 Debian 架构选择官方 release 资产，避免在 ARM64 服务器上拉错二进制。
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) mihomo_arch="amd64"; mihomo_sha256="${MIHOMO_SHA256_AMD64}" ;; \
        arm64) mihomo_arch="arm64"; mihomo_sha256="${MIHOMO_SHA256_ARM64}" ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/mihomo-linux-${mihomo_arch}-${MIHOMO_VERSION}.gz" -o /tmp/mihomo.gz; \
    echo "${mihomo_sha256}  /tmp/mihomo.gz" | sha256sum -c -; \
    gunzip /tmp/mihomo.gz; \
    install -m 0755 /tmp/mihomo /usr/local/bin/mihomo; \
    mihomo -v; \
    rm -f /tmp/mihomo

# 复制源码到容器
COPY src/ .
COPY design/ design/

# 修复启动脚本换行符并赋予执行权限
RUN dos2unix start.sh && chmod +x start.sh

# 创建规则集目录 (持久化准备)
RUN mkdir -p data ruleset

# 暴露 Streamlit 和 FastAPI 端口
EXPOSE 8501 8000

# 赋予启动脚本执行权限
RUN chmod +x start.sh

# 健康检查同时覆盖 Web UI 和订阅 API，任一服务异常都让容器进入 unhealthy。
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health && curl --fail http://localhost:8000/health

# 启动命令
CMD ["./start.sh"]
