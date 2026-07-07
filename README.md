# passwdpm · 服务端加解密密码管理器

一个面向团队的 **密码 + 文件保险箱**。**加解密全部在服务器端完成**：客户端只负责录入与展示明文，密钥由服务器自动生成。适用于需要集中托管密钥、审计密码变更、按分组隔离可见性的内部场景。

## 加密体系（先看这里）

本工具在服务端用三种机制处理数据，**默认走零知识方案**，服务端永远拿不到你密码的明文：

| 数据类型 | 默认加密方案 | 服务端能否解出明文 | 说明 |
| --- | --- | --- | --- |
| **密码条目** | `entry` —— 每条独立的「条目密码」做 PBKDF2-SM3 + SM4-CBC 对称加密 | ❌ **不能** | 默认行为。服务端只存 salt/iv/密文，没有条目密码还原不了明文。 |
| **密码条目（旧数据）** | `legacy` —— 服务端 GPG/SM2 密钥对 | ✅ 能 | 兼容旧版本数据（升级前历史记录）。 |
| **文件保险箱** | 服务端 GPG 或 SM2 公钥加密 | ✅ 能 | 文件通常由组织统一管理，依赖服务端密钥；上传/解密/删除均记审计。 |

> **零知识方案的含义**：即便数据库泄露，没有条目密码依然无法还原明文。
> 条目密码**不会**被持久化，每次查看/修改由用户在客户端输入、随请求传入 HTTPS。

## 功能

- ✅ **零知识密码存储**：每条密码由用户自己的「条目密码」保护（PBKDF2-SM3 + SM4-CBC），服务端不可解密。
- ✅ **完整 CRUD**：密码查看 / 新增 / 修改 / 删除；新增可选择加密算法（对称零知识 / GPG / SM2）；等待窗口保证后台解析完再消失。
- ✅ **文件保险箱**：上传任意文件，服务端用 GPG 或 SM2 公钥加密落盘；可下载密文或解密下载原文；上传 / 解密 / 删除均记审计。
- ✅ **组织密钥库**：在「密钥库」页签查看 / 生成 / 导入 / 导出本组织下的 GPG 与 SM2 密钥对；公钥下载便于给他人加密、私钥下载自留；按组织隔离，非管理员只看自己所属组织。
- ✅ **修改记录（审计日志）**：每次新增、修改、删除都留下时间、操作人、变更说明，仅存密文快照不存明文。
- ✅ **多账号 + 分组隔离**：管理员可新增账号；数据（密码 / 文件）按分组绑定，普通用户只看到所属分组的数据，管理员可跨组查看。
- ✅ **系统管理面板**：在界面上管理账号（创建 / 编辑 / 删除 / 分配分组）和分组（创建 / 编辑成员 / 删除，分组有数据时阻止删除）。
- ✅ **简单登录**：JWT 登录（`passlib` + `bcrypt`）。
- ✅ **SQLite 本地存储**：零外部依赖，开箱即用。平滑迁移：旧库首次启动自动加列、存量数据归入默认分组。
- ✅ **完全离线可用**：前端无 CDN 依赖，加解密全部为纯 Python 实现（`pgpy` / `gmssl`），运行时无任何外部网络请求。

## 技术栈

| 层 | 选型 |
| --- | --- |
| 后端 | Python + FastAPI + SQLAlchemy |
| 加密 | `pgpy`（GPG/OpenPGP）、`gmssl`（SM2 / SM3 / SM4） |
| 存储 | SQLite |
| 认证 | JWT（PyJWT）+ bcrypt |
| 前端 | 原生 HTML / CSS / JS（由后端静态托管） |

## 目录结构

```
pwd-web/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI 入口，挂载 API 与静态资源
│   │   ├── config.py            # 配置（端口、密钥、管理员）
│   │   ├── db.py                # SQLAlchemy 引擎 / Session
│   │   ├── models.py            # User / Group / KeyRecord / PasswordEntry / History / FileVault / FileHistory
│   │   ├── security.py          # 密码哈希 + JWT
│   │   ├── seed.py              # 首次启动初始化（建表、管理员、默认分组、密钥）
│   │   ├── crypto/
│   │   │   ├── gpg_crypto.py    # GPG/OpenPGP 加解密（pgpy）
│   │   │   ├── sm2_crypto.py    # SM2 加解密（gmssl）
│   │   │   ├── entry_cipher.py  # 条目密码对称加密（PBKDF2-SM3 + SM4-CBC）
│   │   │   └── manager.py       # 算法分发与密钥读取
│   │   ├── core/deps.py         # 认证与分组权限依赖
│   │   ├── routers/             # auth / passwords / files / history / keys / admin
│   │   └── static/              # 前端 index.html / app.js / styles.css
│   ├── run.py                   # 启动脚本
│   ├── requirements.txt
│   ├── Dockerfile               # 容器镜像构建（支持离线 / 联网两种依赖来源）
│   ├── offline/                 # 离线部署套件（build_image、get_wheels、install、systemd）
│   └── .env.example
├── docker-compose.yml           # 容器编排（端口 / 卷 / 环境变量，platform=linux/amd64）
└── README.md
```

## 快速开始（直接跑 Python）

### 1. 准备 Python 虚拟环境（推荐 3.13）

```bash
cd backend
python -m venv venv
# Windows
venv\Scripts\pip install -r requirements.txt
# 或 macOS / Linux
python -m venv venv && venv/bin/pip install -r requirements.txt
```

### 2. 配置环境变量（可选）

复制 `backend/.env.example` 为 `backend/.env` 并按需修改，**至少改掉默认管理员密码**：

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

### 4. 使用（首次添加密码）

1. 用管理员登录后，在「密码」页签点 **新增密码**。
2. 填写标题 / 账号 / 密码明文 / 备注 / **所属分组**。
3. **必填：条目密码**（用于加密这一条；后续查看 / 修改本条都需再次输入）。
4. 保存后，列表里会出现这一条；点击查看需输入刚才设置的「条目密码」。

> ⚠️ **条目密码一旦忘记无法找回**（这是零知识方案的代价）。

## 离线部署（不用 Docker，纯 Python）

本工具**完全离线可用**：前端无 CDN，加解密均为纯 Python 实现（`pgpy` / `gmssl`），运行时不访问任何外部网络。只需在离线服务器上装好 Python（建议 3.13）并装好依赖。

### 第 1 步：在一台「联网且与目标服务器 OS / Python 版本相同」的机器上准备依赖包

```bash
# Windows
backend\offline\get_wheels.bat
# Linux / macOS
bash backend/offline/get_wheels.sh
```

这会把所有依赖（含 `pgpy` 源码包构建所需的 setuptools / wheel）下载到 `backend/offline/wheels/`。

> ⚠️ 依赖包是**平台相关**的（`cryptography` / `bcrypt` / `watchfiles` 等含编译产物）。
> 若目标服务器是 **Linux**，必须在同架构的 Linux 机器上跑 `get_wheels.sh`；
> 当前仓库自带的 `offline/wheels/` 是 **Windows** 版本，仅供 Windows 目标服务器直接使用。
> 若目标为 Linux x86_64，也可在任意联网机器上跨平台下载：
> ```bash
> pip download -r requirements.txt setuptools wheel \
>   --platform manylinux2014_x86_64 --python-version 313 --abi cp313 \
>   --dest offline/wheels
> ```

### 第 2 步：把整个项目拷贝到离线服务器，安装依赖

将含 `backend/offline/wheels/` 的整个目录拷贝到离线服务器，然后：

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

### 平台与架构

- **目标服务器**：Linux x86_64（标准）。
- **构建脚本已固化 `--platform linux/amd64`**：即便构建主机是 Apple Silicon（arm64），也会产出可在 x86_64 服务器运行的镜像（通过 QEMU 模拟）。
- **`docker-compose.yml` 也已声明 `platform: linux/amd64`**，compose up / build 行为一致。

### 第 1 步：在联网机器上构建并导出镜像

```bash
# 联网构建（依赖从 PyPI 拉取），导出为 backend/offline/passwdpm_image.tar
bash backend/offline/build_image.sh          # Linux / macOS
# 或  backend\offline\build_image.bat         # Windows

# 完全离线构建（依赖来自 offline/wheels 中已准备好的 Linux 版依赖包）
bash backend/offline/build_image.sh offline
```

导出后的 tar 包约 **70MB**（依赖干净的基础功能版本）；启用组织密钥库后约 **141MB**（含 `pgpy` / `gmssl`）。

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
> docker run -d --name passwdpm --platform linux/amd64 \
>   -p 9010:9010 \
>   -v $(pwd)/backend/data:/app/data \
>   -e ADMIN_PASSWORD='请改成强密码' \
>   --restart unless-stopped \
>   passwdpm:latest
> ```

启动后访问 <http://localhost:9010> 。`docker-compose.yml` 已做：

- 端口映射 `${PORT:-9010}:9010`
- 数据卷 `./backend/data:/app/data`（数据库 + JWT 密钥 + 文件保险箱全部持久化）
- `restart: unless-stopped` 自动重启
- 强制 `platform: linux/amd64`

> 若是 Windows 目标服务器，直接用 **Docker Desktop + 联网构建** 即可，无需 tar 包搬运：
> 在该机器上 `docker compose up -d --build` 即可（要求 Docker Desktop 能访问 PyPI）。

## 安全说明

- **明文走网络**：加解密在服务端进行，查看 / 新增时条目密码会通过 HTTP 传输。生产环境务必启用 **HTTPS**（反向代理如 Nginx / Caddy 配置 TLS）。
- **私钥保护**：数据库中 GPG / SM2 私钥以明文存储（仅用于兼容旧 `legacy` 密码条目 + 文件保险箱）。生产环境建议：
  - 对 `data/passwdpm.db` 做文件权限限制与备份加密；
  - 或将私钥字段改为使用主密钥（环境变量 `SECRET_KEY`）加密后再落库。
- **零知识密码条目不受私钥泄露影响**：因条目密码独立派生 SM4 密钥，服务端密钥仅兼容 legacy 数据。
- **JWT 有效期**：默认 24 小时，可用 `TOKEN_EXPIRE_MINUTES` 调整。
- **CORS**：当前为 `allow_origins=["*"]`，仅适用于内网工具部署；公网部署请收敛 origin。

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/auth/login` | 登录获取 token |
| GET | `/api/auth/me` | 当前用户（含可见分组） |
| GET | `/api/keys/status` | 服务端密钥就绪情况（兼容 legacy 方案 / 文件保险箱） |
| GET | `/api/orgkeys?group_id=` | 组织密钥库列表（按组织过滤；非管理员看自己所属组织） |
| POST | `/api/orgkeys/generate` | 新建密钥（GPG / SM2，公私钥完整生成） |
| POST | `/api/orgkeys/import` | 导入密钥（公钥必填、私钥可选；带 round-trip 自检） |
| GET | `/api/orgkeys/{kid}/export?kind=public\|private` | 导出公钥 / 私钥为附件下载（双 Content-Disposition 兼容中文文件名） |
| DELETE | `/api/orgkeys/{kid}` | 删除密钥记录 |
| GET | `/api/passwords` | 密码列表（不含明文） |
| POST | `/api/passwords` | 新增（**必填**：`title` `secret` `group_id` `entry_password`） |
| GET | `/api/passwords/{id}?entry_password=...` | 查看（`legacy` 免条目密码，`entry` 必须提供） |
| PUT | `/api/passwords/{id}` | 修改（`entry` 方案需 `entry_password`；可选 `new_entry_password` 改密） |
| DELETE | `/api/passwords/{id}` | 删除（软删除 + 记审计） |
| GET | `/api/passwords/{id}/history` | 修改记录 |
| POST | `/api/files/upload` | 上传文件并加密（form: `file` + `algorithm` + **`group_id`**） |
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

每条密码的变更都会保存在 `history` 表，前端「记录」按钮可查看：

| 时间 | 动作 | 标题 | 账号 | 算法 | 操作人 | 说明 |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-07-07 11:00 | 新增 | 数据库 root | root | symmetric | admin | 新增密码 |
| 2026-07-07 15:20 | 修改 | 数据库 root | root | symmetric | admin | 修改了 secret |