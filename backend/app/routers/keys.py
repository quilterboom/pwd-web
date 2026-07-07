from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.deps import (
    ensure_group_access,
    get_current_user,
    get_user_group_ids,
)
from ..crypto import manager
from ..db import get_db
from ..models import KeyRecord, OrgKey, User

router = APIRouter(tags=["keys"])


# ============================================================
# 已有：服务端密钥状态（用于密码/文件 legacy 方案的就绪检查）
# ============================================================
@router.get("/api/keys/status")
def keys_status(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    present = {r.algorithm: True for r in db.query(KeyRecord).all()}
    return {algo: present.get(algo, False) for algo in manager.SUPPORTED}


# ============================================================
# 新增：组织密钥库（按组织维度的多密钥管理）
# ============================================================
orgkeys_router = APIRouter(
    prefix="/api/orgkeys",
    tags=["orgkeys"],
    dependencies=[Depends(get_current_user)],
)


class GenerateRequest(BaseModel):
    name: str
    algorithm: str  # 'gpg' | 'sm2'
    group_id: int
    comment: str = ""


class ImportRequest(BaseModel):
    name: str
    algorithm: str  # 'gpg' | 'sm2'
    group_id: int
    public_key: str = ""   # armored PEM（GPG）或 hex（SM2）
    private_key: str = ""  # armored PEM（GPG）或 hex（SM2）
    comment: str = ""


def _fingerprint(algorithm: str, public_key: str) -> str:
    """为密钥计算可读指纹——GPG 用 PGPKey 的真实指纹，SM2 取公钥前 16 hex + 散列前 8 hex。"""
    try:
        if algorithm == "gpg":
            import sys, types
            if "imghdr" not in sys.modules:
                _imghdr = types.ModuleType("imghdr")
                _imghdr.what = lambda file, h=None: None
                sys.modules["imghdr"] = _imghdr
            import pgpy
            pub = pgpy.PGPKey.from_blob(public_key)[0]
            return str(pub.fingerprint).replace(" ", "").upper()
    except Exception:
        pass
    pub = (public_key or "").strip()
    if len(pub) >= 16:
        return pub[:8] + "…" + pub[-8:]
    return pub[:16] or "?"


def _validate_keys(algorithm: str, public_key: str, private_key: str = "") -> None:
    """校验用户上传/粘贴的密钥格式是否可解析。失败抛 400。"""
    if algorithm not in ("gpg", "sm2"):
        raise HTTPException(status_code=400, detail=f"不支持的算法: {algorithm}")
    if not public_key:
        raise HTTPException(status_code=400, detail="缺少公钥内容")
    provider = manager.get_provider(algorithm)
    try:
        provider.encrypt("passwdpm-test", public_key)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"公钥格式无效：{e}") from e
    if private_key:
        try:
            provider.decrypt(provider.encrypt("passwdpm-test-roundtrip", public_key), private_key)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"私钥与公钥不匹配或无效：{e}") from e


def _export_filename(rec: OrgKey, kind: str) -> str:
    """生成 ASCII 安全的下载头文件名（防 HTTP header latin-1 编码失败）。"""
    safe = "".join(
        c if c.isascii() and (c.isalnum() or c in ".-_") else "_"
        for c in (rec.name or "key")
    )
    if rec.algorithm == "gpg":
        ext = ".asc"
    else:
        ext = ".key"
    suffix = "_pub" if kind == "public" else "_priv"
    return f"{safe}{suffix}{ext}"


def _pretty_filename(rec: OrgKey, kind: str) -> str:
    """人类可读文件名（保留原始中文名，先进浏览器优先用此字段）。"""
    suffix = "_pub" if kind == "public" else "_priv"
    ext = ".asc" if rec.algorithm == "gpg" else ".key"
    pretty = (rec.name or "key").replace("\r", " ").replace("\n", " ")
    return f"{pretty}{suffix}{ext}"


@orgkeys_router.get("")
def list_orgkeys(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    group_id: int | None = Query(default=None),
):
    """列出当前用户所属组织（或指定组织）下的密钥。"""
    q = db.query(OrgKey)
    if not user.is_admin:
        visible = get_user_group_ids(db, user)
        if not visible:
            return []
        q = q.filter(OrgKey.group_id.in_(visible))
    if group_id is not None:
        q = q.filter(OrgKey.group_id == group_id)
    rows = q.order_by(OrgKey.group_id.asc(), OrgKey.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "algorithm": r.algorithm,
            "group_id": r.group_id,
            "fingerprint": r.fingerprint,
            "has_private": r.has_private,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in rows
    ]


@orgkeys_router.post("/generate")
def generate_orgkey(req: GenerateRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if req.algorithm not in manager.SUPPORTED:
        raise HTTPException(status_code=400, detail=f"不支持的算法: {req.algorithm}")
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="请输入密钥名称")
    ensure_group_access(db, user, req.group_id)

    pub, priv = manager.get_provider(req.algorithm).generate_keypair()
    fp = _fingerprint(req.algorithm, pub)
    rec = OrgKey(
        group_id=req.group_id,
        name=req.name.strip(),
        algorithm=req.algorithm,
        public_key=pub,
        private_key=priv,
        fingerprint=fp,
        has_private=True,
        created_by=user.username,
    )
    db.add(rec)
    db.commit()
    return {"id": rec.id, "fingerprint": fp, "algorithm": rec.algorithm, "has_private": rec.has_private}


@orgkeys_router.post("/import")
def import_orgkey(req: ImportRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="请输入密钥名称")
    ensure_group_access(db, user, req.group_id)
    has_priv = bool(req.private_key.strip())
    _validate_keys(req.algorithm, req.public_key, req.private_key)
    fp = _fingerprint(req.algorithm, req.public_key)
    rec = OrgKey(
        group_id=req.group_id,
        name=req.name.strip(),
        algorithm=req.algorithm,
        public_key=req.public_key.strip(),
        private_key=req.private_key.strip() if has_priv else None,
        fingerprint=fp,
        has_private=has_priv,
        created_by=user.username,
    )
    db.add(rec)
    db.commit()
    return {"id": rec.id, "fingerprint": fp, "has_private": has_priv}


@orgkeys_router.get("/{kid}/export")
def export_orgkey(
    kid: int,
    kind: str = Query(default="public", pattern="^(public|private)$"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """导出公钥或私钥为文本/二进制附件下载。"""
    rec = db.query(OrgKey).filter_by(id=kid).first()
    if rec is None:
        raise HTTPException(status_code=404, detail="密钥不存在")
    ensure_group_access(db, user, rec.group_id)
    if kind == "public":
        body = rec.public_key
        if rec.algorithm == "sm2":
            body_bytes = body.encode("utf-8")
            media = "text/plain"
        else:
            body_bytes = body.encode("utf-8")
            media = "application/pgp-keys"
        fname = _export_filename(rec, "public")
    else:  # private
        if not rec.private_key:
            raise HTTPException(status_code=404, detail="该密钥未持有私钥")
        body = rec.private_key
        body_bytes = body.encode("utf-8")
        media = "application/pgp-keys" if rec.algorithm == "gpg" else "text/plain"
        fname = _export_filename(rec, "private")

    from urllib.parse import quote
    ascii_fname = _export_filename(rec, kind)
    pretty_fname = _pretty_filename(rec, kind)
    return Response(
        content=body_bytes,
        media_type=media,
        headers={
            "Content-Disposition": (
                f"attachment; filename=\"{ascii_fname}\"; "
                f"filename*=UTF-8''{quote(pretty_fname)}"
            )
        },
    )


@orgkeys_router.delete("/{kid}")
def delete_orgkey(kid: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rec = db.query(OrgKey).filter_by(id=kid).first()
    if rec is None:
        raise HTTPException(status_code=404, detail="密钥不存在")
    ensure_group_access(db, user, rec.group_id)
    db.delete(rec)
    db.commit()
    return {"ok": True}
