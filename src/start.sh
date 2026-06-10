#!/bin/bash
set -e

# 启动 FastAPI 服务 (后台运行)
# 端口 8000 用于 API
uvicorn api:app --host 0.0.0.0 --port 8000 &
api_pid=$!

# 启动 Streamlit 服务
# 端口 8501 用于 Web UI
streamlit run web_app.py --server.address=0.0.0.0 --server.port=8501 &
web_pid=$!

trap 'kill "$api_pid" "$web_pid" 2>/dev/null || true' INT TERM

# 任一服务退出都让容器退出，避免 API 挂掉但健康检查仍显示正常。
wait -n "$api_pid" "$web_pid"
exit_code=$?
kill "$api_pid" "$web_pid" 2>/dev/null || true
exit "$exit_code"
