#!/bin/bash
# 容器入口：以 root 启动时先修正数据目录归属，再用 setpriv 降权为 app (10001) 重新执行自身；
# 降权后同时运行 FastAPI 与 Streamlit，任一退出即整体退出。
set -eu

APP_UID=10001
APP_GID=10001

if [ "$(id -u)" = "0" ]; then
    # 数据卷来自宿主机，目录可能属 root；只修正归属不一致的条目，重复启动开销很小。
    for dir in /app/data /app/ruleset; do
        mkdir -p "$dir"
        # 归属修正失败时降权后 SQLite 会只读而健康检查仍绿，必须直接失败退出。
        if ! find "$dir" -xdev \( ! -uid "$APP_UID" -o ! -gid "$APP_GID" \) -exec chown "$APP_UID:$APP_GID" {} +; then
            echo "错误：无法修正 $dir 的归属为 $APP_UID:$APP_GID，请检查挂载目录权限" >&2
            exit 1
        fi
    done
    export HOME=/home/app
    exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups -- "$0" "$@"
fi

# 启动 FastAPI 服务 (后台运行)，保留访问日志（token 过滤由 api.py 负责）
# 端口 8000 用于 API
uvicorn api:app --host 0.0.0.0 --port 8000 &
api_pid=$!

# 启动 Streamlit 服务
# 端口 8501 用于 Web UI
streamlit run web_app.py --server.address=0.0.0.0 --server.port=8501 &
web_pid=$!

# 收到 TERM/INT 时转发给两个子进程，由下面的 wait 流程统一收尾。
forward_signal() {
    kill -TERM "$api_pid" "$web_pid" 2>/dev/null || true
}
trap forward_signal INT TERM

# 任一服务退出都让容器退出，避免 API 挂掉但健康检查仍显示正常。
# set -e 下 wait -n 返回非零会直接退出脚本，这里临时关闭以便拿到退出码并清理另一个进程。
set +e
wait -n "$api_pid" "$web_pid"
exit_code=$?
set -e

kill -TERM "$api_pid" "$web_pid" 2>/dev/null || true
# 回收子进程；若 20 秒内仍未退出（对应 stop_grace_period）则强制结束。
for _ in $(seq 1 15); do
    kill -0 "$api_pid" 2>/dev/null || kill -0 "$web_pid" 2>/dev/null || break
    sleep 1
done
kill -KILL "$api_pid" "$web_pid" 2>/dev/null || true
wait "$api_pid" "$web_pid" 2>/dev/null || true
exit "$exit_code"
