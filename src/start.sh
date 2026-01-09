#!/bin/bash

# 启动 FastAPI 服务 (后台运行)
# 端口 8000 用于 API
uvicorn api:app --host 0.0.0.0 --port 8000 &

# 启动 Streamlit 服务
# 端口 8501 用于 Web UI
streamlit run web_app.py --server.address=0.0.0.0 --server.port=8501
