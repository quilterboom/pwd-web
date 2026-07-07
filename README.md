# passwdpm · 服务端加解密密码管理器

一个基于 **GPG (OpenPGP)** 与 **SM2 (国密)** 的密码管理工具。**加解密全部在服务器端完成**：客户端只负责录入明文、展示明文，密钥由服务器自动生成并保管。适用于需要集中托管密钥、审计密码变更的团队场景。

## 功能

- ✅ **服务端加解密**：密钥对由服务器自动生成（GPG / SM2 各一套），明文不落库。
- ✅ **每条记录可选算法**：新增/编辑时可选择用 GPG 还是 SM2 加密。
- ✅ **密码查看 / 新增 / 修改 / 删除**：完整 CRUD。
- ✅ **修改记录（审计日志）**：每次新增、修改、删除都会留下时间、操作人、变更说明，且只保存密文快照，绝不记录明文。
- ✅ **文件保险箱**：除密码文本外，还能**上传并加密任意文件**（GPG 或 SM2）。文件在服务端用所选算法公钥加密后落盘，可「下载密文」或「解密下载原文」，解密/上传/删除均记入审计。加密过程参考 PassPy：GPG 走 OpenPGP 混合加密（pgpy），SM2 走国密 KDF（gmssl），均支持二进制与任意长度。
- ✅ **多账号 + 分组隔离**：支持管理员**新增账号**，所有数据（密码 / 文件）按**分组**绑定，用户只能看到自己所属分组的数据；管理员可跨组查看全部。每个用户的 `/me` 返回其可见分组，新建数据时必须选所属分组。
- ✅ **系统管理面板**：管理员可在界面上管理账号（创建 / 编辑 / 删除 / 分配分组）与分组（创建 / 编辑成员 / 删除，删除前会阻止仍有数据的分组）。
- ✅ **简单登录**：基于 JWT 的账号登录（`passlib` + `bcrypt`）。
- ✅ **SQLite 本地存储**：零外部依赖，开箱即用。平滑迁移：旧库首次启动会自动加列、并把存量数据归到默认分组，数据不丢。

## 技术栈

| 层 | 选型 |
| --- | --- |
| 后端 | Python + FastAPI + SQLAlchemy |
| 加密 | `pgpy`（GPG/OpenPGP）、`gmssl`（SM2） |
| 存储 | SQLite |
| 认证 | JWT（PyJWT）+ bcrypt |
| 前端 | 原生 HTML / CSS / JS（由后端静态托管） |

## 目录结构

```
passwdpm-web/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI 入口，挂载 API 与静态资源
│   │   ├── config.py        # 配置（端口、密钥、管理员）
│   │   ├── db.py            # SQLAlchemy 引擎 / Session
│   │   ├── models.py        # User / Group / KeyRecord / PasswordEntry / History / FileVault / FileHistory
│   │   ├── security.py      # 密码哈希 + JWT
│   │   ├── seed.py          # 首次启动初始化（建表、管理员、默认分组、密钥）
│   │   ├── crypto/          # gpg_crypto.py / sm2_crypto.py / manager.py
│   │   ├── core/deps.py     # 认证与分组权限依赖
│   │   ├── routers/         # auth / passwords / files / history / keys / admin
│   │   └── static/          # 前端 index.html / app.js / styles.css
│   ├── run.py               # 启动脚本
│   ├── requirements.txt
│   └── .env.example
├── backend/
│   ├── Dockerfile        # 容器镜像构建（支持离线 / 联网两种依赖来源）
│   ├── offline/          # 离线部署套件（含 build_image 脚本）
│   ├── requirements.txt
│   └── .env.example
├── docker-compose.yml    # 容器编排（端口 / 卷 / 环境变量）
└── README.md
```

## 快速开始

### 1. 准备 Python 虚拟环境（使用 3.13 已验证）

```bash
cd backend
python -m venv venv
# Windows
venv\Scripts\pip install -r requirements.txt
# 或 macOS / Linux
python -m venv venv && venv/bin/pip install -r requirements.txt
```

### 2. 配置环境变量（可选）

复制 `backend/.env.example` 为 `backend/.env` 并按需修改，至少建议改掉默认管理员密码：

```ini
ADMIN_USERNAME=admin
ADMIN_PASSWORD=请改成强密码
```

> 若不设置 `SECRET_KEY`，服务会在 `backend/data/.secret_key` 自动生成并持久化，避免重启后令牌失效。

### 3. 启动

```bash
# 在 backend/ 目录下
venv\Scripts\python run.py        # Windows
# 或
venv/bin/python run.py            # macOS / Linux
```

启动后访问 <http://localhost:9010> ，使用环境变量中的管理员账号登录（默认 `admin / admin123`）。

## 离线部署

本工具**完全离线可用**：前端无 CDN 依赖，加解密均为纯 Python 实现（pgpy / gmssl），运行时不访问任何外部网络。只需在离线服务器上装好 Python（建议 3.13）并装好依赖即可。

### 第 1 步：在一台「联网且与目标服务器 OS / Python 版本相同」的机器上准备依赖包

```bash
# Windows
backend\offline\get_wheels.bat
# Linux / macOS
bash backend/offline/get_wheels.sh
```

这会把所有依赖（含 pgpy 源码包构建所需的 setuptools / wheel）下载到 `backend/offline/wheels/`。

> ⚠️ 依赖包是**平台相关**的（cryptography / bcrypt / watchfiles 等含编译产物）。
> 若目标服务器是 **Linux**，必须在同架构的 Linux 机器上跑 `get_wheels.sh`；
> 当前仓库自带的 `offline/wheels/` 是 **Windows** 版本，仅供 Windows 目标服务器直接使用。
> 若目标为 Linux x86_64，也可在任意联网机器上跨平台下载：
> ```bash
> pip download -r requirements.txt setuptools wheel \
>   --platform manylinux2014_x86_64 --python-version 313 --abi cp313 \
>   --dest offline/wheels
> ```

### 第 2 步：把整个项目拷贝到离线服务器，安装依赖

将含 `backend/offline/wheels/` 的整个 `passwdpm-web` 目录拷贝到离线服务器，然后：

```bash
# Windows
backend\offline\install.bat
# Linux / macOS
bash backend/offline/install.sh
```

脚本会创建本地 `venv` 并用 `--no-index` 从本地 wheels 安装，**全程不联网**。

### 第 3 步：启动

```bash
# Windows
backend\venv\Scripts\python run.py
# Linux
backend/venv/bin/python run.py
```

建议修改管理员密码（环境变量 `ADMIN_USERNAME` / `ADMIN_PASSWORD`，或写 `backend/.env`）。

### Linux 以系统服务常驻（systemd）

示例单元文件见 `backend/offline/passwdpm.service`。部署时：

```bash
# 假设项目放在 /opt/passwdpm，并创建专用用户 passwdpm
sudo cp backend/offline/passwdpm.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now passwdpm
```

## Docker 部署

容器镜像**自包含**：依赖在构建期已固化进镜像，运行时零联网，非常适合离线服务器。

整体思路：在一台**能联网**的机器上构建镜像并导出成 tar 包，再把 tar 包与 `docker-compose.yml` 一起拷到离线服务器加载运行。

### 第 1 步：在联网机器上构建并导出镜像

```bash
# 联网构建（依赖从 PyPI 拉取），导出为 backend/offline/passwdpm_image.tar
bash backend/offline/build_image.sh          # Linux / macOS
# 或  backend\offline\build_image.bat         # Windows

# 完全离线构建（依赖来自 offline/wheels 中已准备好的 Linux 版依赖包）
bash backend/offline/build_image.sh offline
```

> ⚠️ 离线构建时，`backend/offline/wheels/` 必须是 **Linux (manylinux x86_64, cp313)** 版依赖包，
> 可用 `get_wheels.sh` 配合 `--platform manylinux2014_x86_64 --python-version 313 --abi cp313` 在任意联网机下载。

### 第 2 步：在离线服务器加载并启动

```bash
# 1) 加载镜像（无需联网）
docker load -i backend/offline/passwdpm_image.tar

# 2) 启动（建议先用环境变量覆盖管理员密码）
ADMIN_PASSWORD='请改成强密码' docker compose up -d
```

> ⚠️ 若离线服务器是老版 Docker（缺 compose v2 插件），`docker compose` 会报
> `unknown shorthand flag: 'd'`。请改用 `docker run`：
> ```bash
> docker run -d --name passwdpm -p 9010:9010 \
>   -v $(pwd)/backend/data:/app/data \
>   -e ADMIN_PASSWORD='请改成强密码' \
>   --restart unless-stopped \
>   passwdpm:latest
> ```

启动后访问 <http://localhost:9010> 。`docker-compose.yml` 已做：

- 端口映射 `${PORT:-9010}:9010`
- 数据卷 `./backend/data:/app/data`（数据库 + JWT 密钥持久化）
- `restart: unless-stopped` 自动重启

> 若是 Windows 目标服务器，直接用 **Docker Desktop + 联网构建** 即可，无需 tar 包搬运：
> 在该机器上 `docker compose up -d --build` 即可（要求 Docker Desktop 能访问 PyPI）。

## 安全说明

- **明文走网络**：由于加解密在服务端进行，查看/新增时明文会通过 HTTP 传输。生产环境务必启用 **HTTPS**（反向代理如 Nginx / Caddy 配置 TLS）。
- **私钥保护**：数据库中的私钥以明文存储。生产环境建议：
  - 对 `data/passwdpm.db` 做文件权限限制与备份加密；
  - 或将私钥字段改为使用主密钥（环境变量 `SECRET_KEY`）加密后再落库（当前版本为明文，便于本地使用）。
- **JWT 有效期**：默认 24 小时，可用 `TOKEN_EXPIRE_MINUTES` 调整。

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/auth/login` | 登录获取 token |
| GET | `/api/auth/me` | 当前用户 |
| GET | `/api/keys/status` | 服务端密钥就绪情况 |
| GET | `/api/passwords` | 密码列表（不含明文） |
| POST | `/api/passwords` | 新增（服务端加密） |
| GET | `/api/passwords/{id}` | 查看（服务端解密返回明文） |
| PUT | `/api/passwords/{id}` | 修改（重新加密 + 记审计） |
| DELETE | `/api/passwords/{id}` | 删除（软删除 + 记审计） |
| GET | `/api/passwords/{id}/history` | 修改记录 |
| POST | `/api/files/upload` | 上传文件并在服务端加密（form: file + algorithm） |
| GET | `/api/files` | 文件保险箱列表（不含密文） |
| GET | `/api/files/{id}/download` | 下载加密后的密文文件（.gpg / .sm2） |
| GET | `/api/files/{id}/decrypt` | 服务端解密后下载原文（记审计） |
| DELETE | `/api/files/{id}` | 删除（软删除 + 记审计） |
| GET | `/api/files/{id}/history` | 文件修改记录（上传 / 解密 / 删除） |
| GET | `/api/groups/mine` | 当前用户可见分组（用于创建数据时的下拉） |
| GET | `/api/admin/users` | 账号列表（仅管理员） |
| POST | `/api/admin/users` | 新增账号（含分组归属） |
| PUT | `/api/admin/users/{uid}` | 编辑账号（密码 / 管理员标记 / 分组） |
| DELETE | `/api/admin/users/{uid}` | 删除账号 |
| GET | `/api/admin/groups` | 分组列表（含成员） |
| POST | `/api/admin/groups` | 新增分组（含成员） |
| PUT | `/api/admin/groups/{gid}` | 编辑分组（名称 / 成员） |
| DELETE | `/api/admin/groups/{gid}` | 删除分组（有数据时阻止） |

## 修改记录（审计）示例

每条记录的变更都会保存在 `history` 表，前端「记录」按钮可查看：

| 时间 | 动作 | 标题 | 账号 | 算法 | 操作人 | 说明 |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-07-07 11:00 | 新增 | 数据库 root | root | GPG | admin | 新增密码 |
| 2026-07-07 15:20 | 修改 | 数据库 root | root | GPG | admin | 修改了 secret |
