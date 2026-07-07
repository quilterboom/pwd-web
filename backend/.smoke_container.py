"""容器内真实冒烟测试：通过 HTTP 直连运行中的容器，验证镜像本身已含多账号+分组隔离功能。"""
import json, urllib.request, urllib.error, sys

BASE = "http://localhost:9015"
ADMIN_U, ADMIN_P = "admin", "admin123"

fails = []
def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (("  => " + extra) if extra and not cond else ""))
    if not cond:
        fails.append(name)

def req(method, path, token=None, json_body=None, data=None, files=None):
    url = BASE + path
    if files is not None:
        import io, random, string
        boundary = "----passwdpm" + "".join(random.choices(string.ascii_letters, k=12))
        body = io.BytesIO()
        if data:
            for k, v in data.items():
                body.write(f"--{boundary}\r\n".encode())
                body.write(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
                body.write(str(v).encode()); body.write(b"\r\n")
        for k, (fn, content, ctype) in files.items():
            body.write(f"--{boundary}\r\n".encode())
            body.write(f'Content-Disposition: form-data; name="{k}"; filename="{fn}"\r\n'.encode())
            body.write(f"Content-Type: {ctype}\r\n\r\n".encode())
            body.write(content); body.write(b"\r\n")
        body.write(f"--{boundary}--\r\n".encode())
        data_bytes = body.getvalue()
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    elif json_body is not None:
        data_bytes = json.dumps(json_body).encode()
        headers = {"Content-Type": "application/json"}
    else:
        data_bytes = None
        headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    r = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def login(u, p):
    st, body = req("POST", "/api/auth/login", json_body={"username": u, "password": p})
    assert st == 200, (u, st, body)
    return json.loads(body)["access_token"]

def auth(t): return t

# 1) 管理员登录 + /me
t_admin = login(ADMIN_U, ADMIN_P)
st, body = req("GET", "/api/auth/me", token=t_admin)
me = json.loads(body)
check("admin is_admin true", me.get("is_admin") is True, str(me))
check("admin has default group", any(g["name"] == "默认分组" for g in me.get("groups", [])), str(me.get("groups")))

# 2) 创建两个分组
st, body = req("POST", "/api/admin/groups", token=t_admin, json_body={"name": "研发组", "description": ""})
g1 = json.loads(body); check("create group 研发组", st == 200 and "id" in g1, str((st, body)))
st, body = req("POST", "/api/admin/groups", token=t_admin, json_body={"name": "财务组", "description": ""})
g2 = json.loads(body); check("create group 财务组", st == 200 and "id" in g2, str((st, body)))

# 3) 创建两个普通用户，分属不同分组
st, body = req("POST", "/api/admin/users", token=t_admin, json_body={"username": "alice", "password": "pw1", "group_ids": [g1["id"]]})
u1 = json.loads(body); check("create user alice", st == 200 and "id" in u1, str((st, body))); u1_id = u1["id"]
st, body = req("POST", "/api/admin/users", token=t_admin, json_body={"username": "bob", "password": "pw2", "group_ids": [g2["id"]]})
u2 = json.loads(body); check("create user bob", st == 200 and "id" in u2, str((st, body))); u2_id = u2["id"]

# 4) 重复用户名 409
st, _ = req("POST", "/api/admin/users", token=t_admin, json_body={"username": "alice", "password": "x"})
check("duplicate user 409", st == 409, "status=%s" % st)

# 5) 普通用户登录
t_alice = login("alice", "pw1")
t_bob = login("bob", "pw2")
st, body = req("GET", "/api/auth/me", token=t_alice)
me_a = json.loads(body)
check("alice sees only 研发组", [g["name"] for g in me_a.get("groups", [])] == ["研发组"], str(me_a.get("groups")))
check("alice not admin", me_a.get("is_admin") is False)

# 6) alice 在研发组创建密码 + 文件
st, body = req("POST", "/api/passwords", token=t_alice, json_body={"title": "rds", "username": "u", "algorithm": "sm2", "secret": "secret-A", "group_id": g1["id"]})
pid = json.loads(body).get("id") if st == 200 else None
check("alice create pw in g1", st == 200 and pid is not None, str((st, body)))
st, _ = req("POST", "/api/passwords", token=t_alice, json_body={"title": "x", "algorithm": "sm2", "secret": "y"})
check("create pw without group_id rejected", st == 422, "status=%s" % st)
st, _ = req("POST", "/api/passwords", token=t_alice, json_body={"title": "x", "algorithm": "sm2", "secret": "y", "group_id": g2["id"]})
check("alice write to g2 -> 403", st == 403, "status=%s" % st)
st, body = req("POST", "/api/files/upload", token=t_alice, data={"algorithm": "gpg", "group_id": str(g1["id"])}, files={"file": ("a.txt", b"hello-bytes", "text/plain")})
fid = json.loads(body).get("id") if st == 200 else None
check("alice upload file in g1", st == 200 and fid is not None, str((st, body)))

# 7) 隔离：bob 看不到 alice 的数据
st, body = req("GET", "/api/passwords", token=t_bob)
lst = json.loads(body)
check("bob cannot see alice pw", all(e["id"] != pid for e in lst), str([e["id"] for e in lst]))
st, body = req("GET", "/api/files", token=t_bob)
lst = json.loads(body)
check("bob cannot see alice file", all(e["id"] != fid for e in lst), str([e["id"] for e in lst]))
st, _ = req("GET", f"/api/passwords/{pid}", token=t_bob)
check("bob access alice pw -> 403", st == 403, "status=%s" % st)
st, _ = req("GET", f"/api/passwords/{pid}/history", token=t_bob)
check("bob access alice history -> 403", st == 403, "status=%s" % st)

# 8) 管理员可见全部
st, body = req("GET", "/api/passwords", token=t_admin)
lst = json.loads(body)
check("admin sees alice pw", any(e["id"] == pid for e in lst), str([e["id"] for e in lst]))
st, body = req("GET", "/api/files", token=t_admin)
lst = json.loads(body)
check("admin sees alice file", any(e["id"] == fid for e in lst), str([e["id"] for e in lst]))

# 9) alice 解密自己的明文
st, body = req("GET", f"/api/passwords/{pid}", token=t_alice)
check("alice decrypts own secret", st == 200 and json.loads(body).get("secret") == "secret-A", str((st, body)))

# 10) 普通用户不能访问管理接口
st, _ = req("GET", "/api/admin/users", token=t_alice)
check("alice blocked from admin", st == 403, "status=%s" % st)

# 11) 把 bob 加入研发组后可见 alice 的密码（通过 PUT 更新分组成员）
st, body = req("PUT", f"/api/admin/groups/{g1['id']}", token=t_admin, json_body={"member_ids": [u1_id, u2_id]})
member_ok = st in (200, 201)
check("add bob to 研发组 via admin", member_ok, str((st, body)))
st, body = req("GET", "/api/passwords", token=t_bob)
lst = json.loads(body)
check("bob sees alice pw after group join", any(e["id"] == pid for e in lst), str([e["id"] for e in lst]))

# 12) 删除仍绑定数据的分组应被阻止
st, _ = req("DELETE", f"/api/admin/groups/{g1['id']}", token=t_admin)
check("delete group with data blocked", st == 400, "status=%s" % st)
req("DELETE", f"/api/passwords/{pid}", token=t_alice)
req("DELETE", f"/api/files/{fid}", token=t_alice)
st, _ = req("DELETE", f"/api/admin/groups/{g1['id']}", token=t_admin)
check("delete empty group ok", st == 200, "status=%s" % st)

print("\n=== %d failed ===" % len(fails))
if fails:
    for f in fails: print("  -", f)
    sys.exit(1)
print("ALL PASS (container image verified)")
