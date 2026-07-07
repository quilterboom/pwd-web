from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.deps import (
    ensure_group_access,
    get_current_user,
    get_user_group_ids,
    visibility_filter,
)
from ..crypto import entry_cipher, manager
from ..db import get_db
from ..models import History, PasswordEntry, User

router = APIRouter(
    prefix="/api/passwords",
    tags=["passwords"],
    dependencies=[Depends(get_current_user)],
)


class CreateRequest(BaseModel):
    title: str
    username: str = ""
    secret: str
    notes: str = ""
    comment: str = ""
    group_id: int  # 必填：数据绑定的分组
    entry_password: str  # 条目密码：每条密码独立对称加密，查看/修改均需此密码


class UpdateRequest(BaseModel):
    title: Optional[str] = None
    username: Optional[str] = None
    algorithm: Optional[str] = None
    secret: Optional[str] = None
    notes: Optional[str] = None
    comment: str = ""
    entry_password: Optional[str] = None  # 当前条目密码（scheme=entry 时必填，用于解密现有内容）
    new_entry_password: Optional[str] = None  # 可选：修改为新条目密码后重新加密


def _serialize_meta(e: PasswordEntry) -> dict:
    return {
        "id": e.id,
        "title": e.title,
        "username": e.username,
        "algorithm": e.algorithm,
        "scheme": e.scheme,
        "needs_password": e.scheme == "entry",
        "notes": e.notes,
        "group_id": e.group_id,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "updated_at": e.updated_at.isoformat() if e.updated_at else None,
        "created_by": e.created_by,
        "updated_by": e.updated_by,
    }


def _require_algorithm(algo: Optional[str]) -> Optional[str]:
    if algo is None:
        return None
    if algo not in manager.SUPPORTED:
        raise HTTPException(status_code=400, detail=f"不支持的算法: {algo}")
    return algo


def _encrypt_for_create(req: CreateRequest) -> dict:
    """新密码一律用「条目密码」做对称加密（PBKDF2-SM3 + SM4-CBC），服务端不持有密钥。"""
    enc = entry_cipher.encrypt_entry(req.secret, req.entry_password)
    return {
        "algorithm": "symmetric",
        "scheme": "entry",
        "ciphertext": enc["ciphertext"],
        "entry_salt": enc["salt"],
        "entry_iv": enc["iv"],
    }


def _decrypt_entry_secret(db: Session, e: PasswordEntry, entry_password: Optional[str]) -> str:
    """解密单条密码明文。entry 方案必须提供且正确，否则抛对应 HTTP 异常。
    legacy 方案（旧数据）由服务端密钥解密，无需条目密码。"""
    if e.scheme == "entry":
        if not entry_password:
            raise HTTPException(
                status_code=400,
                detail="该密码由「条目密码」保护，请提供 entry_password 才能查看",
            )
        try:
            return entry_cipher.decrypt_entry(
                {"salt": e.entry_salt, "iv": e.entry_iv, "ciphertext": e.ciphertext},
                entry_password,
            )
        except entry_cipher.WrongPasswordError:
            raise HTTPException(status_code=401, detail="条目密码错误，无法解密")
    # legacy：服务端密钥解密（兼容旧数据）
    return manager.decrypt_secret(db, e.algorithm, e.ciphertext)


@router.get("")
def list_passwords(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    gids = get_user_group_ids(db, user)
    f = visibility_filter(PasswordEntry.group_id, user, gids)
    q = db.query(PasswordEntry).filter_by(deleted=False)
    if f is not None:
        q = q.filter(f)
    rows = q.order_by(PasswordEntry.updated_at.desc()).all()
    return [_serialize_meta(r) for r in rows]


@router.post("")
def create(
    req: CreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_group_access(db, user, req.group_id)

    fields = _encrypt_for_create(req)
    entry = PasswordEntry(
        title=req.title,
        username=req.username,
        notes=req.notes,
        group_id=req.group_id,
        created_by=user.username,
        updated_by=user.username,
        **fields,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    db.add(
        History(
            password_id=entry.id,
            group_id=entry.group_id,
            action="create",
            title=entry.title,
            username=entry.username,
            algorithm=entry.algorithm,
            ciphertext=entry.ciphertext,
            notes=entry.notes,
            changed_by=user.username,
            comment=req.comment or "新增密码",
        )
    )
    db.commit()
    return {"id": entry.id, "message": "created"}


@router.get("/{pid}")
def get_one(
    pid: int,
    entry_password: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    entry = db.query(PasswordEntry).filter_by(id=pid, deleted=False).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="未找到该密码")
    ensure_group_access(db, user, entry.group_id)
    secret = _decrypt_entry_secret(db, entry, entry_password)
    return {**_serialize_meta(entry), "secret": secret}


@router.put("/{pid}")
def update(
    pid: int,
    req: UpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    entry = db.query(PasswordEntry).filter_by(id=pid, deleted=False).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="未找到该密码")
    ensure_group_access(db, user, entry.group_id)

    changes: list[str] = []
    if req.title is not None and req.title != entry.title:
        entry.title = req.title
        changes.append("title")
    if req.username is not None and req.username != entry.username:
        entry.username = req.username
        changes.append("username")
    if req.notes is not None and req.notes != entry.notes:
        entry.notes = req.notes
        changes.append("notes")

    if entry.scheme == "entry":
        # 条目密码方案：必须先解密现有内容，再按需重新加密
        if not req.entry_password:
            raise HTTPException(status_code=400, detail="修改受「条目密码」保护的密码必须提供 entry_password")
        try:
            current_secret = entry_cipher.decrypt_entry(
                {"salt": entry.entry_salt, "iv": entry.entry_iv, "ciphertext": entry.ciphertext},
                req.entry_password,
            )
        except entry_cipher.WrongPasswordError:
            raise HTTPException(status_code=401, detail="条目密码错误，无法修改")

        new_secret = req.secret if req.secret is not None else current_secret
        if req.secret is not None and req.secret != current_secret:
            changes.append("secret")

        algo = entry.algorithm
        if req.algorithm is not None and req.algorithm != entry.algorithm:
            _require_algorithm(req.algorithm)
            algo = req.algorithm

        # 用新密码（或沿用当前密码）重新加密
        enc_pw = req.new_entry_password or req.entry_password
        enc = entry_cipher.encrypt_entry(new_secret, enc_pw)
        entry.algorithm = algo
        entry.scheme = "entry"
        entry.ciphertext = enc["ciphertext"]
        entry.entry_salt = enc["salt"]
        entry.entry_iv = enc["iv"]
        if req.new_entry_password:
            changes.append("entry_password")
    else:
        # legacy：服务端密钥加密
        algo = entry.algorithm
        if req.algorithm is not None and req.algorithm != entry.algorithm:
            _require_algorithm(req.algorithm)
            algo = req.algorithm

        if req.secret is not None or algo != entry.algorithm:
            plain = (
                req.secret
                if req.secret is not None
                else manager.decrypt_secret(db, entry.algorithm, entry.ciphertext)
            )
            entry.algorithm = algo
            entry.ciphertext = manager.encrypt_secret(db, algo, plain)
            if req.secret is not None:
                changes.append("secret")
            if algo != entry.algorithm:
                changes.append("algorithm")

    entry.updated_by = user.username
    entry.updated_at = datetime.now(timezone.utc)
    db.commit()

    db.add(
        History(
            password_id=entry.id,
            group_id=entry.group_id,
            action="update",
            title=entry.title,
            username=entry.username,
            algorithm=entry.algorithm,
            ciphertext=entry.ciphertext,
            notes=entry.notes,
            changed_by=user.username,
            comment=req.comment or ("修改了 " + ",".join(changes) if changes else "无变更"),
        )
    )
    db.commit()
    return {"id": pid, "message": "updated", "changes": changes}


@router.delete("/{pid}")
def delete(
    pid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    entry = db.query(PasswordEntry).filter_by(id=pid, deleted=False).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="未找到该密码")
    ensure_group_access(db, user, entry.group_id)
    entry.deleted = True
    entry.updated_by = user.username
    entry.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.add(
        History(
            password_id=pid,
            group_id=entry.group_id,
            action="delete",
            title=entry.title,
            username=entry.username,
            algorithm=entry.algorithm,
            ciphertext=entry.ciphertext,
            notes=entry.notes,
            changed_by=user.username,
            comment="删除密码",
        )
    )
    db.commit()
    return {"id": pid, "message": "deleted"}
