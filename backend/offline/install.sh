#!/usr/bin/env bash
# ============================================================================
#  离线部署 - 第 2 步：在离线服务器上运行。会从 offline/wheels 本地安装，
#  不访问任何网络。要求本机已安装与目标一致的 Python（建议 3.13）。
# ============================================================================
set -e
cd "$(dirname "$0")/.."
if [ ! -d offline/wheels ]; then
  echo "未找到 offline/wheels，请先在有网的机器上运行 get_wheels.sh"
  exit 1
fi
python3 -m venv venv
source venv/bin/activate
pip install --no-index --find-links offline/wheels -r requirements.txt
echo
echo "安装完成。启动服务：venv/bin/python run.py"
