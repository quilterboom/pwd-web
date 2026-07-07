#!/usr/bin/env bash
# 在「能联网」的机器上执行：构建镜像并导出为 tar 包，用于离线服务器 docker load。
# 用法：
#   bash offline/build_image.sh            # 联网构建（从 PyPI 拉依赖）
#   bash offline/build_image.sh offline    # 离线构建（使用 offline/wheels 里的 Linux 依赖包）
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

IMAGE=passwdpm:latest
TARBALL=backend/offline/passwdpm_image.tar

# 目标服务器是 Linux x86_64；显式指定 platform，避免在 arm64 / 多架构主机上
# 产出无法在目标服务器运行的镜像。
PLATFORM=linux/amd64

if [ "${1:-}" = "offline" ]; then
  # 离线构建：要求 offline/wheels 已是 Linux manylinux 包
  echo ">>> [离线] 构建镜像（依赖来自 offline/wheels，需先准备好 Linux 版依赖包）"
  docker build --no-cache --platform "$PLATFORM" -t "$IMAGE" --build-arg OFFLINE=1 ./backend
else
  echo ">>> [联网] 构建镜像（依赖从 PyPI 拉取）"
  docker build --no-cache --platform "$PLATFORM" -t "$IMAGE" ./backend
fi

echo ">>> 导出镜像到 $TARBALL"
docker save "$IMAGE" -o "$TARBALL"
echo ">>> 完成。请将 backend/offline/passwdpm_image.tar 与 docker-compose.yml 一并拷到离线服务器。"
echo "    离线服务器执行：docker load -i backend/offline/passwdpm_image.tar && docker compose up -d"
