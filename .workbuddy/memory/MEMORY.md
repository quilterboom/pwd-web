# passwdpm / pwd-web 项目长期笔记

## 项目身份
- 路径：`/Users/liuyupengliu/Downloads/projects/pwd-web/`
- 类型：FastAPI + SQLAlchemy + SQLite + pgpy/gmssl 的离线密码/文件保险箱；原生 HTML/CSS/JS 前端；JWT + bcrypt 认证；多租户（按 group_id 隔离）。
- 部署目标：内网离线 x86_64 Linux 服务器（Docker 镜像分发）。

## 加密体系（重要，很容易搞混）
- **entry 方案（默认）**——PBKDF2-SM3 派生 SM4-CBC key，客户端条目密码不落库，零知识。`PasswordEntry.scheme == 'entry'`。
- **legacy 方案（兼容）**——用服务端 KeyRecord（GPG/SM2）加密，`scheme == 'legacy'`。PUT 允许 entry↔legacy 切换，需旧 entry_password 解密。
- **文件保险箱**——目前仍走服务端 KeyRecord（`FileVault.algorithm`），不要求条目密码。`/api/files/upload` 需要 `group_id`。

## 关键模块/路径
- `backend/app/models.py`：`User` `Group` `user_groups`（Table，非 ORM 类） `PasswordEntry` `FileVault` `History` `FileHistory` `KeyRecord` `OrgKey`。
- `backend/app/routers/keys.py`：`/api/keys/status`（服务端密钥就绪） + `/api/orgkeys/*`（多密钥 CRUD）。
- `backend/app/crypto/gpg_crypto.py` 顶部 stub `imghdr`（Python 3.13 PEP 594 移除）。同样的 stub 也用于 `routers/keys.py` 的 `_fingerprint`。
- `backend/app/core/deps.py`：权限核心——`get_current_user` `get_user_group_ids` `visibility_filter` `ensure_group_access` `require_admin`。多对多用 `user_groups` Table 对象，没有 `UserGroup` 模型类。
- `backend/Dockerfile`：`python:3.13-slim` 基础；可 `--build-arg OFFLINE=1` 走离线 wheels。
- `backend/offline/passwdpm_image.tar`：当前 **141MB**（含 OrgKey 库），旧 71MB 是无密钥库版本。

## 易踩的坑
1. **pgpy 在 Python 3.13 缺 `imghdr`**——必须 import 前 `sys.modules['imghdr']` 注入 stub。`routers/keys.py` 也得做一次（`_fingerprint`）。
2. **passlib 1.7.4 ≠ bcrypt>=4.1**——必须固定 `bcrypt==4.0.1`。
3. **gmssl SM2 公钥不会自动由私钥推导**——`CryptSM2(...)._kg(int(priv,16), ecc_table['g'])` 算 Q=priv*G。
4. **HTTP 导出中文文件名**——`Content-Disposition` 必须双字段：`filename="ASCII"` + `filename*=UTF-8''<urlencoded>`；`isascii() and (c.isalnum() or c in ".-_")` 过滤非法字符。
5. **SQLAlchemy 多对多无 ORM 类**——`user_groups.insert()/.delete()`，不能 `UserGroup(...)`。
6. **Docker Desktop 内存小（3.8GiB）+ `--no-cache`**——`pip install` step 直接 SIGKILL。改用 `docker commit`：run→cp→rm data→commit，复用旧依赖层。
7. **arm64 Mac 产 x86_64 镜像**——所有 `docker build` 显式 `--platform linux/amd64`，compose `build.platforms: [linux/amd64]` + `platform: linux/amd64`。
8. **WorkBuddy zsh sandbox subshell 打 curl**——用 `/usr/bin/curl` 绝对路径；管道用 `> /tmp/x` + `python3` 两步。
9. **daocloud 镜像源 401**——`~/.docker/daemon.json` 的 `registry-mirrors` 已失效，先移除再 build。

## 端到端验证模式
- 容器内跑测试 = 绕开主机 sandbox 的最稳方法：`docker cp script.py X:/tmp/ && docker exec X python3 /tmp/script.py`。
- 17 项基础断言（entry + 多租户 + 文件 + OrgKey）覆盖：登录、JWT、groups/mine、新增 entry、错误条目密码 401、正确解密还原、修改改条目密码、history ≥ 2、GPG/SM2 文件、1MB 二进制 md5 一致、文件审计、密钥状态、未授权 401、OrgKey 9 项。
- 测试容器：`docker run -d --name passwdpm-test --platform linux/amd64 -p 9010:9010 -v /tmp/passwdpm-test-data:/app/data -e ADMIN_PASSWORD='TestPass!2026' passwdpm:latest`。
- admin/TestPass!2026 是当前测试数据卷里的账号。

## 最近一次镜像
- `passwdpm:latest` ID `5f71b1e79b19`，462MB（虚拟），141MB（tar）。
- commit `604fda8` 是 feature 集大成：算法选择 + 等待窗口 + OrgKey 库 + 多租户 + 文件保险箱 + entry 零知识。
