"""端到端测试：多账号 + 分组隔离 + 管理接口。"""
import os, sys, tempfile
# 用临时目录作为数据目录，避免污染离线服务器数据目录，且文件型 SQLite 跨连接共享
_tmpdir = tempfile.mkdtemp(prefix="passwdpm_smoke_")
os.environ["DATA_DIR"] = _tmpdir
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["ADMIN_PASSWORD"] = "admin123"
os.environ["ADMIN_USERNAME"] = "admin"

sys.path.insert(0, os.path.dirname(__file__))

from app.main import app
from app.db import SessionLocal
from app import seed
from app.models import User, Group, user_groups, PasswordEntry, FileVault
from app.security import hash_password

seed.seed()

from fastapi.testclient import TestClient
c = TestClient(app)

def login(u, p):
    r = c.post("/api/auth/login", json={"username": u, "password": p})
    assert r.status_code == 200, (u, r.text)
    return r.json()["access_token"]

def auth(t): return {"Authorization": f"Bearer {t}"}

fails = []
def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond: fails.append(name)

# 1) 管理员登录 + /me
t_admin = login("admin", "admin123")
me = c.get("/api/auth/me", headers=auth(t_admin)).json()
check("admin is_admin true", me["is_admin"] is True)
check("admin has default group", any(g["name"] == "默认分组" for g in me["groups"]))

# 2) 管理员创建两个分组
g1 = c.post("/api/admin/groups", headers=auth(t_admin), json={"name": "研发组", "description": ""}).json()
g2 = c.post("/api/admin/groups", headers=auth(t_admin), json={"name": "财务组", "description": ""}).json()
check("create groups", "id" in g1 and "id" in g2)

# 3) 创建两个普通用户，分别归到不同分组
u1 = c.post("/api/admin/users", headers=auth(t_admin), json={"username": "alice", "password": "pw1", "group_ids": [g1["id"]]}).json()
u2 = c.post("/api/admin/users", headers=auth(t_admin), json={"username": "bob", "password": "pw2", "group_ids": [g2["id"]]}).json()
check("create users", "id" in u1 and "id" in u2)

# 4) 重复用户名应 409
r = c.post("/api/admin/users", headers=auth(t_admin), json={"username": "alice", "password": "x"})
check("duplicate user 409", r.status_code == 409)

# 5) 普通用户登录
t_alice = login("alice", "pw1")
t_bob = login("bob", "pw2")
me_a = c.get("/api/auth/me", headers=auth(t_alice)).json()
check("alice sees only 研发组", [g["name"] for g in me_a["groups"]] == ["研发组"])
check("alice not admin", me_a["is_admin"] is False)

# 6) alice 在研发组创建密码 + 文件
r = c.post("/api/passwords", headers=auth(t_alice), json={"title": "rds", "username": "u", "algorithm": "sm2", "secret": "secret-A", "group_id": g1["id"]})
check("alice create pw in g1", r.status_code == 200)
pid = r.json()["id"]
# 缺 group_id 应 422
r = c.post("/api/passwords", headers=auth(t_alice), json={"title": "x", "algorithm": "sm2", "secret": "y"})
check("create pw without group_id rejected", r.status_code == 422)
# alice 不能写入不属于自己的分组 g2 -> 403
r = c.post("/api/passwords", headers=auth(t_alice), json={"title": "x", "algorithm": "sm2", "secret": "y", "group_id": g2["id"]})
check("alice write to g2 -> 403", r.status_code == 403)

files = {"file": ("a.txt", b"hello-bytes", "text/plain")}
r = c.post("/api/files/upload", headers=auth(t_alice), data={"algorithm": "gpg", "group_id": str(g1["id"])}, files=files)
check("alice upload file in g1", r.status_code == 200)
fid = r.json()["id"]

# 7) 隔离：bob 看不到 alice 的数据
r = c.get("/api/passwords", headers=auth(t_bob)).json()
check("bob cannot see alice pw", all(e["id"] != pid for e in r))
r = c.get("/api/files", headers=auth(t_bob)).json()
check("bob cannot see alice file", all(e["id"] != fid for e in r))
# bob 越权访问 alice 的密码 -> 403
r = c.get(f"/api/passwords/{pid}", headers=auth(t_bob))
check("bob access alice pw -> 403", r.status_code == 403)
# bob 越权历史 -> 403
r = c.get(f"/api/passwords/{pid}/history", headers=auth(t_bob))
check("bob access alice history -> 403", r.status_code == 403)

# 8) 管理员可以看到全部
r = c.get("/api/passwords", headers=auth(t_admin)).json()
check("admin sees alice pw", any(e["id"] == pid for e in r))
r = c.get("/api/files", headers=auth(t_admin)).json()
check("admin sees alice file", any(e["id"] == fid for e in r))

# 9) alice 解密查看自己的明文
r = c.get(f"/api/passwords/{pid}", headers=auth(t_alice)).json()
check("alice decrypts own secret", r["secret"] == "secret-A")

# 10) 普通用户不能访问管理接口 -> 403
r = c.get("/api/admin/users", headers=auth(t_alice))
check("alice blocked from admin", r.status_code == 403)

# 11) 把 bob 加入研发组后，bob 应能看到 alice 的密码
db = SessionLocal()
bob = db.query(User).filter_by(username="bob").first()
db.execute(user_groups.insert().values(user_id=bob.id, group_id=g1["id"]))
db.commit(); db.close()
r = c.get("/api/passwords", headers=auth(t_bob)).json()
check("bob sees alice pw after group join", any(e["id"] == pid for e in r))

# 12) 删除仍绑定数据的分组应被阻止
r = c.delete(f"/api/admin/groups/{g1['id']}", headers=auth(t_admin))
check("delete group with data blocked", r.status_code == 400)
# 先删数据再删分组（密码 + 文件都需清理）
c.delete(f"/api/passwords/{pid}", headers=auth(t_alice))
c.delete(f"/api/files/{fid}", headers=auth(t_alice))
r = c.delete(f"/api/admin/groups/{g1['id']}", headers=auth(t_admin))
check("delete empty group ok", r.status_code == 200)

print("\n=== %d failed ===" % len(fails))
if fails:
    for f in fails: print("  -", f)
    sys.exit(1)
print("ALL PASS")
