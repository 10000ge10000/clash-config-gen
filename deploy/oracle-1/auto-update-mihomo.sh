#!/usr/bin/env bash
# mihomo 内核自动更新（服务器每日 cron 调用）。
#
# 只在 origin/main 比本地多出的提交“只改了 Dockerfile 里的 MIHOMO_* 参数”时才自动部署，
# 这类提交由 .github/workflows/mihomo-update.yml 生成；main 上有其他改动时一律跳过，
# 避免把未确认的业务代码带上线。
#
# 流程：快进源码 → 打回滚镜像（保留最近 5 份）→ 构建新镜像 → 用新内核只读校验全部已发布订阅
#      → 切换容器 → 等待健康检查。任一步失败都恢复旧镜像和旧源码。
#
# cron 示例（北京时间每天 04:30）：
#   30 4 * * * /opt/clash-config-gen/deploy/oracle-1/auto-update-mihomo.sh >> /var/log/clash-config-gen-mihomo-update.log 2>&1
# 只检查不部署：DRY_RUN=1 /opt/clash-config-gen/deploy/oracle-1/auto-update-mihomo.sh
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/clash-config-gen}"
COMPOSE_FILE="$REPO_DIR/deploy/oracle-1/docker-compose.yml"
PROJECT="${COMPOSE_PROJECT:-clash-config-gen}"
CONTAINER="${CONTAINER_NAME:-clash-gen}"
IMAGE="${IMAGE_NAME:-clash-config-gen-clash-gen}"
KEEP_ROLLBACKS=5

log() { echo "[$(date '+%F %T')] $*"; }

exec 9>/var/lock/clash-config-gen-mihomo-update.lock
flock -n 9 || { log "已有更新任务在运行，跳过"; exit 0; }

cd "$REPO_DIR"
git fetch -q origin main
OLD_HEAD=$(git rev-parse HEAD)
NEW_HEAD=$(git rev-parse origin/main)
[ "$OLD_HEAD" = "$NEW_HEAD" ] && { log "源码已是最新，无需更新"; exit 0; }

if ! git merge-base --is-ancestor "$OLD_HEAD" "$NEW_HEAD"; then
  log "本地提交不是 origin/main 的祖先，无法快进，跳过"; exit 0
fi
if ! git diff --quiet HEAD; then
  log "本地源码有未提交改动，跳过：$(git diff --name-only HEAD | tr '\n' ' ')"; exit 0
fi
CHANGED=$(git diff --name-only "$OLD_HEAD" "$NEW_HEAD")
if [ "$CHANGED" != "Dockerfile" ]; then
  log "main 上有 Dockerfile 以外的改动，需人工部署，跳过：$(echo "$CHANGED" | tr '\n' ' ')"; exit 0
fi
if git diff -U0 "$OLD_HEAD" "$NEW_HEAD" -- Dockerfile | grep -E '^[+-][^+-]' | grep -qv '^[+-]ARG MIHOMO_'; then
  log "Dockerfile 有 mihomo 版本以外的改动，需人工部署，跳过"; exit 0
fi

OLD_VERSION=$(git show "$OLD_HEAD:Dockerfile" | sed -n 's/^ARG MIHOMO_VERSION=//p')
NEW_VERSION=$(git show "$NEW_HEAD:Dockerfile" | sed -n 's/^ARG MIHOMO_VERSION=//p')
log "发现 mihomo 更新：$OLD_VERSION -> $NEW_VERSION"
if [ "${DRY_RUN:-0}" = "1" ]; then log "DRY_RUN=1，只检查不部署"; exit 0; fi

DATA_DIR=$(docker inspect "$CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Source}}{{end}}{{end}}')
[ -n "$DATA_DIR" ] || { log "找不到容器 $CONTAINER 的数据目录，跳过"; exit 1; }

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
ROLLBACK="$IMAGE:rollback-$STAMP"
docker tag "$IMAGE:latest" "$ROLLBACK"
log "已打回滚镜像 $ROLLBACK"
docker images --format '{{.Tag}}' "$IMAGE" | grep '^rollback-' | sort | head -n -"$KEEP_ROLLBACKS" \
  | while read -r tag; do docker rmi "$IMAGE:$tag" >/dev/null && log "删除旧回滚镜像 $tag"; done

restore() {
  log "恢复旧版本：$1"
  docker tag "$ROLLBACK" "$IMAGE:latest"
  git reset -q --keep "$OLD_HEAD"
  if [ "${2:-}" = "restart" ]; then
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --no-build
  fi
  exit 1
}

git merge -q --ff-only "$NEW_HEAD"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" build -q || restore "镜像构建失败"
log "新镜像内核：$(docker run --rm --entrypoint mihomo "$IMAGE:latest" -v | head -1)"

docker run --rm --user 10001:10001 --entrypoint python -e PYTHONPATH=/app -w /app \
  -v "$DATA_DIR:/app/data:ro" -v "$REPO_DIR/deploy/oracle-1/validate_published.py:/validate_published.py:ro" \
  "$IMAGE:latest" /validate_published.py || restore "新内核校验已发布订阅未通过"

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --no-build
status=starting
for _ in $(seq 1 40); do
  status=$(docker inspect "$CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null || echo missing)
  [ "$status" = "healthy" ] && break
  sleep 3
done
[ "$status" = "healthy" ] || restore "新容器健康检查未通过（$status）" restart
log "升级完成：$(docker exec "$CONTAINER" mihomo -v | head -1)"
