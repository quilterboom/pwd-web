#!/usr/bin/env bash
# ============================================================================
#  离线部署 - 第 1 步：在【与目标离线服务器操作系统 / Python 版本相同】的
#  联网机器上运行本脚本，把所有依赖下载到 offline/wheels/ 目录。
#  随后把整个项目（含 offline/wheels）拷贝到离线服务器，运行 install.sh。
# ============================================================================
set -e
cd "$(dirname "$0")/.."
mkdir -p offline/wheels
pip3 download -r requirements.txt setuptools wheel -d offline/wheels
echo
echo "下载完成。请将整个项目目录拷贝到离线服务器，然后运行 ./offline/install.sh"
