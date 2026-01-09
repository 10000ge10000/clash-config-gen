# 使用官方 Python Slim 镜像减少体积
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量，防止 Python 生成 pyc 文件，并让 stdout/stderr 直接输出
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 复制依赖文件并安装 (利用 Docker 缓存层)
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 安装 dos2unix 和 curl (用于健康检查)
RUN apt-get update && apt-get install -y dos2unix curl && rm -rf /var/lib/apt/lists/*

# 复制源码到容器
COPY src/ .

# 修复启动脚本换行符并赋予执行权限
RUN dos2unix start.sh && chmod +x start.sh

# 创建规则集目录 (持久化准备)
RUN mkdir -p ruleset

# 暴露 Streamlit 和 FastAPI 端口
EXPOSE 8501 8000

# 赋予启动脚本执行权限
RUN chmod +x start.sh

# 健康检查 (检查 Streamlit)
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

# 启动命令
CMD ["./start.sh"]