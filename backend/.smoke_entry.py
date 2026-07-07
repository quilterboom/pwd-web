"""条目密码（entry 方案）端到端冒烟测试。

不依赖 Docker：用 FastAPI TestClient 起一个临时 DATA_DIR 实例，
验证「新增用条目密码加密、查看/修改须输入对应密码」全链路，并验证旧 legacy 数据兼容。
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TMP = tempfile.mkdtemp(prefix="pw_entry_test_")
os.environ["DATA_DIR"] = TMP
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "admin123"

FAILED = 0


def check(name, ok, info=""):
    global FAILED
    status = "PASS" if ok else "FAIL"
    line = f"[{status}] {name}"
    if not ok:
        FAILED += 1
        line += "  -> " + (info[:300] if info else "")
    print(line)


from fastapi.testclient import TestClient
from app.main import app

with TestClient(app) as client:
    # 登录
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    check("admin 登录", r.status_code == 200, r.text)
    token = r.json()["access_token"]
    H = {"Authorization": f"Bearer {token}"}

    # 默认分组
    me = client.get("/api/auth/me", headers=H).json()
    gid = me["groups"][0]["id"]
    check("获取默认分组", isinstance(gid, int), str(me))

    # 1) 新增条目密码
    r = client.post(
        "/api/passwords",
        headers=H,
        json={
            "title": "db-root",
            "username": "root",
            "secret": "SuperSecret123",
            "entry_password": "pw1",
            "group_id": gid,
            "notes": "n",
        },
    )
    check("新增条目密码", r.status_code == 200, r.text)
    pid = r.json()["id"]

    # 2) 列表不含明文，且标记 needs_password
    lst = client.get("/api/passwords", headers=H).json()
    rec = next(x for x in lst if x["id"] == pid)
    check("列表不含 secret", "secret" not in rec, str(rec))
    check("标记 needs_password", rec.get("needs_password") is True, str(rec))
    check("scheme=entry", rec.get("scheme") == "entry", str(rec))

    # 3) 无密码查看 -> 400
    r = client.get(f"/api/passwords/{pid}", headers=H)
    check("无密码查看被拒(400)", r.status_code == 400, r.text)

    # 4) 错误密码查看 -> 401
    r = client.get(f"/api/passwords/{pid}?entry_password=wrong", headers=H)
    check("错误密码查看被拒(401)", r.status_code == 401, r.text)

    # 5) 正确密码查看
    r = client.get(f"/api/passwords/{pid}?entry_password=pw1", headers=H)
    check("正确密码查看成功", r.status_code == 200 and r.json().get("secret") == "SuperSecret123", r.text)

    # 6) 用正确密码修改 secret
    r = client.put(
        f"/api/passwords/{pid}",
        headers=H,
        json={"entry_password": "pw1", "secret": "NewSecret456"},
    )
    check("用正确密码修改", r.status_code == 200, r.text)
    r = client.get(f"/api/passwords/{pid}?entry_password=pw1", headers=H)
    check("修改后新明文可见", r.json().get("secret") == "NewSecret456", r.text)

    # 7) 用错误密码修改 -> 401
    r = client.put(
        f"/api/passwords/{pid}",
        headers=H,
        json={"entry_password": "bad", "secret": "x"},
    )
    check("错误密码修改被拒(401)", r.status_code == 401, r.text)

    # 8) 更换条目密码
    r = client.put(
        f"/api/passwords/{pid}",
        headers=H,
        json={"entry_password": "pw1", "new_entry_password": "pw2"},
    )
    check("更换条目密码", r.status_code == 200, r.text)
    r = client.get(f"/api/passwords/{pid}?entry_password=pw1", headers=H)
    check("换密后旧密码失效(401)", r.status_code == 401, r.text)
    r = client.get(f"/api/passwords/{pid}?entry_password=pw2", headers=H)
    check("换密后新密码可用", r.status_code == 200 and r.json().get("secret") == "NewSecret456", r.text)

    # 9) legacy 旧数据兼容：直接插入一条服务端密钥加密的记录，无需条目密码即可查看
    from app.crypto import manager
    from app.db import SessionLocal
    from app.models import PasswordEntry

    db = SessionLocal()
    ct = manager.encrypt_secret(db, "gpg", "LegacyPlain")
    db.add(
        PasswordEntry(
            title="legacy",
            username="u",
            algorithm="gpg",
            scheme="legacy",
            ciphertext=ct,
            entry_salt="",
            entry_iv="",
            group_id=gid,
            created_by="admin",
            updated_by="admin",
        )
    )
    db.commit()
    lid = db.query(PasswordEntry).filter_by(title="legacy").first().id
    db.close()

    r = client.get(f"/api/passwords/{lid}", headers=H)
    check("legacy 无需密码查看", r.status_code == 200 and r.json().get("secret") == "LegacyPlain", r.text)
    lst = client.get("/api/passwords", headers=H).json()
    lrec = next(x for x in lst if x["id"] == lid)
    check("legacy needs_password=false", lrec.get("needs_password") is False, str(lrec))

print("\n失败项:", FAILED)
sys.exit(1 if FAILED else 0)
