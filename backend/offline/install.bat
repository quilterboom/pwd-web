@echo off
REM ============================================================================
REM  离线部署 - 第 2 步：在离线服务器上运行。会从 offline\wheels 本地安装，
REM  不访问任何网络。要求本机已安装与目标一致的 Python（建议 3.13）。
REM ============================================================================
setlocal
cd /d "%~dp0.."
if not exist offline\wheels (
  echo 未找到 offline\wheels，请先在有网的机器上运行 get_wheels.bat
  exit /b 1
)
python -m venv venv
call venv\Scripts\activate
pip install --no-index --find-links offline\wheels -r requirements.txt
echo.
echo 安装完成。启动服务：venv\Scripts\python run.py
endlocal
