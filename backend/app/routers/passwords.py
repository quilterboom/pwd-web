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
from ..models import History, OrgKey, PasswordEntry, User

router = APIRouter(
    prefix="/api/passwords",
    tags=["passwords"],
    dependencies=[Depends(get_current_user)],
)


class CreateRequest(BaseModel):
    title: Optional[str] = None  # 已取消必填；保留字段仅用于审计/兼容历史
    username: str = ""
    secret: str
    notes: str = ""
    comment: str = ""
    group_id: int  # 必填：数据绑定的分组
    algorithm: str = "symmetric"  # 'symmetric' = 条目密码对称加密；'gpg' / 'sm2' = legacy
    entry_password: str = ""  # algorithm='symmetric' 时必填；其余算法不需要
    orgkey_id: Optional[int] = None  # legacy 方案时使用：选一把本组织 OrgKey 的公钥加密


class UpdateRequest(BaseModel):
    title: Optional[str] = None
    username: Optional[str] = None
    algorithm: Optional[str] = None  # 目标算法：'symmetric' | 'gpg' | 'sm2'（省略则保持原方案）
    secret: Optional[str] = None
    notes: Optional[str] = None
    comment: str = ""
    entry_password: Optional[str] = None  # 当前条目密码（scheme=entry 或目标改 symmetric 时必填）
    new_entry_password: Optional[str] = None  # 仅当目标为 symmetric 时使用（不填则沿用当前/服务端密钥加密）
    orgkey_id: Optional[int] = None  # legacy 方案的目标 OrgKey；省略则保持 / 回退


def _serialize_meta(db: Session, e: PasswordEntry) -> dict:
    key_name = None
    if e.orgkey_id:
        k = db.query(OrgKey).filter_by(id=e.orgkey_id).first()
        if k:
            key_name = k.name
    return {
        "id": e.id,
        "title": e.title or "",
        "username": e.username,
        "algorithm": e.algorithm,
        "scheme": e.scheme,
        "needs_password": e.scheme == "entry",
        "notes": e.notes,
        "group_id": e.group_id,
        "orgkey_id": e.orgkey_id,
        "key_name": key_name,
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


def _resolve_orgkey(db: Session, user: User, orgkey_id: Optional[int], expected_group_id: int) -> Optional[OrgKey]:
    """若传了 orgkey_id：必须在用户可见组织内且与 expected_group_id 相同。"""
    if not orgkey_id:
        return None
    rec = db.query(OrgKey).filter_by(id=orgkey_id).first()
    if rec is None:
        raise HTTPException(status_code=400, detail="指定的 OrgKey 不存在")
    ensure_group_access(db, user, rec.group_id)
    if rec.group_id != expected_group_id:
        raise HTTPException(status_code=400, detail="OrgKey 与数据分组不匹配")
    return rec


def _encrypt_for_create(db: Session, user: User, req: CreateRequest) -> dict:
    """按 algorithm 分流：symmetric → 条目密码方案；gpg/sm2 → OrgKey 公钥（可选）或服务端密钥。"""
    algo = (req.algorithm or "symmetric").lower()
    if algo == "symmetric":
        if not req.entry_password:
            raise HTTPException(
                status_code=400,
                detail="使用「对称加密」必须提供条目密码",
            )
        enc = entry_cipher.encrypt_entry(req.secret, req.entry_password)
        return {
            "algorithm": "symmetric",
            "scheme": "entry",
            "ciphertext": enc["ciphertext"],
            "entry_salt": enc["salt"],
            "entry_iv": enc["iv"],
            "orgkey_id": None,
        }
    if algo in ("gpg", "sm2"):
        orgkey = _resolve_orgkey(db, user, req.orgkey_id, req.group_id)
        if orgkey is not None:
            try:
                ciphertext = manager.get_provider(algo).encrypt(req.secret, orgkey.public_key)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"用 OrgKey 公钥加密失败：{e}") from e
            return {
                "algorithm": algo,
                "scheme": "legacy",
                "ciphertext": ciphertext,
                "entry_salt": "",
                "entry_iv": "",
                "orgkey_id": orgkey.id,
            }
        # 回退：服务端默认密钥（兼容旧数据 + OrgKey 库为空的情况）
        return {
            "algorithm": algo,
            "scheme": "legacy",
            "ciphertext": manager.encrypt_secret(db, algo, req.secret),
            "entry_salt": "",
            "entry_iv": "",
            "orgkey_id": None,
        }
    raise HTTPException(status_code=400, detail=f"不支持的加密方式: {algo}")


def _decrypt_entry_secret(db: Session, e: PasswordEntry, entry_password: Optional[str]) -> str:
    """解密单条密码明文。entry 方案必须提供且正确，否则抛对应 HTTP 异常。
    legacy 方案：若关联 OrgKey 且持有私钥则用 OrgKey 解；否则用服务端默认密钥。"""
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
    # legacy
    if e.orgkey_id:
        k = db.query(OrgKey).filter_by(id=e.orgkey_id).first()
        if k and k.private_key:
            try:
                return manager.get_provider(e.algorithm).decrypt(e.ciphertext, k.private_key)
            except Exception as ex:
                raise HTTPException(
                    status_code=500,
                    detail=f"用 OrgKey 私钥解密失败：{ex}",
                ) from ex
        # 若 OrgKey 已不存在或无私钥，回退到服务端默认密钥
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
    return [_serialize_meta(db, r) for r in rows]


@router.post("")
def create(
    req: CreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ensure_group_access(db, user, req.group_id)

    fields = _encrypt_for_create(db, user, req)
    entry = PasswordEntry(
        title=(req.title or "").strip(),
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
    return {**_serialize_meta(db, entry), "secret": secret}


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
    if req.orgkey_id is not None and req.orgkey_id != entry.orgkey_id:
        changes.append("orgkey_id")

    if entry.scheme == "entry":
        # 当前为条目密码方案
        if not req.entry_password:
            raise HTTPException(status_code=400, detail="修改受「条目密码」保护的密码必须提供 entry_password")
        try:
            current_secret = entry_cipher.decrypt_entry(
                {"salt": entry.entry_salt, "iv": entry.entry_iv, "ciphertext": entry.ciphertext},
                req.entry_password,
            )
        except entry_cipher.WrongPasswordError:
            raise HTTPException(status_code=401, detail="条目密码错误，无法修改")
    else:
        # legacy：先尝试用 OrgKey 私钥解密，失败回退到服务端默认密钥
        current_secret = None
        if entry.orgkey_id:
            k = db.query(OrgKey).filter_by(id=entry.orgkey_id).first()
            if k and k.private_key:
                try:
                    current_secret = manager.get_provider(entry.algorithm).decrypt(entry.ciphertext, k.private_key)
                except Exception:
                    current_secret = None  # 回退
        if current_secret is None:
            current_secret = manager.decrypt_secret(db, entry.algorithm, entry.ciphertext)

    new_secret = req.secret if req.secret is not None else current_secret
    if req.secret is not None and req.secret != current_secret:
        changes.append("secret")

    # 确定目标 scheme 与 algorithm
    target_algo = (req.algorithm or entry.algorithm or "symmetric").lower()
    target_scheme = "entry" if target_algo == "symmetric" else "legacy"
    algo_changed = (target_algo != entry.algorithm) or (
        ("entry" if entry.algorithm == "symmetric" else "legacy") != target_scheme
    )

    # 校验
    if target_algo not in ("symmetric", "gpg", "sm2"):
        raise HTTPException(status_code=400, detail=f"不支持的加密方式: {target_algo}")
    if target_scheme == "entry":
        # entry 方案：用 new_entry_password（沿用当前条目密码）作为加密口令
        enc_pw = req.new_entry_password or req.entry_password
        if not enc_pw:
            raise HTTPException(
                status_code=400,
                detail="切换到「对称加密」必须提供 new_entry_password（或保持当前条目密码）",
            )

    # 按目标方案重新加密
    if target_scheme == "entry":
        enc = entry_cipher.encrypt_entry(new_secret, enc_pw)
        entry.algorithm = "symmetric"
        entry.scheme = "entry"
        entry.ciphertext = enc["ciphertext"]
        entry.entry_salt = enc["salt"]
        entry.entry_iv = enc["iv"]
        entry.orgkey_id = None
    else:
        # legacy：优先用指定的 OrgKey 公钥加密；否则 fallback 到服务端默认密钥
        entry.algorithm = target_algo
        entry.scheme = "legacy"
        orgkey = _resolve_orgkey(db, user, req.orgkey_id, entry.group_id)
        if orgkey is not None:
            try:
                entry.ciphertext = manager.get_provider(target_algo).encrypt(new_secret, orgkey.public_key)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"用 OrgKey 公钥加密失败：{e}") from e
            entry.orgkey_id = orgkey.id
        else:
            entry.ciphertext = manager.encrypt_secret(db, target_algo, new_secret)
            entry.orgkey_id = None
        entry.entry_salt = ""
        entry.entry_iv = ""

    # 变更审计字段
    if target_scheme == "entry" and req.new_entry_password:
        changes.append("entry_password")
    if algo_changed:
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
