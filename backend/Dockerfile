# passwdpm - 服务端 GPG/SM2 加解密密码管理器
# 基础镜像与容器运行时不依赖任何外部网络（依赖在构建期已固化进镜像）。
FROM python:3.13-slim

# 避免 Debian 交互式配置 & 设置 UTF-8 环境
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

WORKDIR /app

# 1) 依赖清单
COPY requirements.txt ./

# 2) 离线依赖包（若存在则离线安装；为空则回退到 PyPI 联网安装）。
#    这样镜像既能联网构建，也能用 offline/wheels 完全离线构建。
COPY offline ./offline

# 默认走 PyPI 联网安装；仅当显式传入 --build-arg OFFLINE=1 时才离线安装。
# 注意：离线安装要求 offline/wheels 内含「与目标容器（Linux x86_64, cp313）同平台」的依赖包，
# 不能直接用仓库里默认的 Windows 版 wheels。
ARG OFFLINE=0
RUN if [ "$OFFLINE" = "1" ]; then \
      echo "[passwdpm] 离线安装（--no-index），需 offline/wheels 含与目标容器同平台的依赖包"; \
      pip install --no-cache-dir --no-index --find-links offline/wheels -r requirements.txt; \
    else \
      echo "[passwdpm] 联网安装（PyPI）"; \
      pip install --no-cache-dir -r requirements.txt; \
    fi

# 3) 应用代码
COPY app ./app
COPY run.py ./

# 数据卷：SQLite 数据库与 JWT 密钥均落在 /app/data，挂载到宿主机以便持久化
VOLUME ["/app/data"]

EXPOSE 9010

# run.py 内部已通过 lifespan 完成建表 / 管理员 / 密钥初始化
CMD ["python", "run.py"]
