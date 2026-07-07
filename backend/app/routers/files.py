"""文件保险箱：服务端加解密任意文件（参考 PassPy 的 GPG/SM2 文件加密过程）。

流程与密码记录一致——密钥由服务器保管，上传的文件在服务端用所选算法（GPG 或 SM2）
的公钥加密后落盘；解密下载时再用服务器私钥还原原文。密文落在 config.FILES_DIR，
数据库只保存元数据与审计日志。所有数据按分组绑定，仅分组内成员可见。
"""
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..config import FILES_DIR
from ..core.deps import (
    ensure_group_access,
    get_current_user,
    get_user_group_ids,
    visibility_filter,
)
from ..crypto import manager
from ..db import get_db
from ..models import FileHistory, FileVault, User

router = APIRouter(
    prefix="/api/files",
    tags=["files"],
    dependencies=[Depends(get_current_user)],
)

ALGO_EXT = {"gpg": "gpg", "sm2": "sm2"}


def _now():
    return datetime.now(timezone.utc)


def _get_entry(db: Session, fid: int) -> FileVault:
    entry = db.query(FileVault).filter_by(id=fid, deleted=False).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="未找到该文件")
    return entry


def _serialize(e: FileVault) -> dict:
    return {
        "id": e.id,
        "filename": e.filename,
        "algorithm": e.algorithm,
        "size": e.size,
        "content_type": e.content_type,
        "group_id": e.group_id,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "updated_at": e.updated_at.isoformat() if e.updated_at else None,
        "created_by": e.created_by,
        "updated_by": e.updated_by,
    }


def _content_disposition(filename: str) -> str:
    # RFC 5987：用 filename* 传递 UTF-8 文件名，兼容中文
    return f"attachment; filename*=UTF-8''{quote(filename)}"


@router.post("/upload")
async def upload(
    file: UploadFile = File(...),
    algorithm: str = Form(...),
    group_id: int = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if algorithm not in manager.SUPPORTED:
        raise HTTPException(status_code=400, detail=f"不支持的算法: {algorithm}")
    ensure_group_access(db, user, group_id)

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="文件为空")

    ciphertext = manager.encrypt_file(db, algorithm, data)

    entry = FileVault(
        filename=file.filename or "unnamed",
        stored_name="",  # 先建行拿 id，再写文件
        algorithm=algorithm,
        size=len(data),
        content_type=file.content_type or "application/octet-stream",
        group_id=group_id,
        created_by=user.username,
        updated_by=user.username,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    ext = ALGO_EXT.get(algorithm, "bin")
    stored_name = f"{entry.id}.{ext}"
    (FILES_DIR / stored_name).write_bytes(ciphertext)
    entry.stored_name = stored_name
    db.commit()

    db.add(
        FileHistory(
            file_id=entry.id,
            group_id=group_id,
            action="upload",
            filename=entry.filename,
            algorithm=algorithm,
            size=len(data),
            changed_by=user.username,
            comment="上传并加密",
        )
    )
    db.commit()
    return {"id": entry.id, "filename": entry.filename, "algorithm": algorithm, "size": len(data)}


@router.get("")
def list_files(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    gids = get_user_group_ids(db, user)
    f = visibility_filter(FileVault.group_id, user, gids)
    q = db.query(FileVault).filter_by(deleted=False)
    if f is not None:
        q = q.filter(f)
    rows = q.order_by(FileVault.updated_at.desc()).all()
    return [_serialize(r) for r in rows]


@router.get("/{fid}/download")
def download_cipher(
    fid: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    """下载加密后的密文文件（.gpg / .sm2）。"""
    entry = _get_entry(db, fid)
    ensure_group_access(db, user, entry.group_id)
    path = FILES_DIR / entry.stored_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="密文文件不存在")
    ext = ALGO_EXT.get(entry.algorithm, "bin")
    return Response(
        content=path.read_bytes(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": _content_disposition(f"{entry.filename}.{ext}")},
    )


@router.get("/{fid}/decrypt")
def decrypt_file(
    fid: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    """在服务端用私钥解密，下载原始文件。会记入审计日志。"""
    entry = _get_entry(db, fid)
    ensure_group_access(db, user, entry.group_id)
    path = FILES_DIR / entry.stored_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="密文文件不存在")
    plaintext = manager.decrypt_file(db, entry.algorithm, path.read_bytes())

    db.add(
        FileHistory(
            file_id=fid,
            group_id=entry.group_id,
            action="decrypt",
            filename=entry.filename,
            algorithm=entry.algorithm,
            size=entry.size,
            changed_by=user.username,
            comment="解密下载原文",
        )
    )
    db.commit()

    return Response(
        content=plaintext,
        media_type=entry.content_type or "application/octet-stream",
        headers={"Content-Disposition": _content_disposition(entry.filename)},
    )


@router.delete("/{fid}")
def delete(
    fid: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    entry = _get_entry(db, fid)
    ensure_group_access(db, user, entry.group_id)
    entry.deleted = True
    entry.updated_by = user.username
    entry.updated_at = _now()
    db.commit()
    db.add(
        FileHistory(
            file_id=fid,
            group_id=entry.group_id,
            action="delete",
            filename=entry.filename,
            algorithm=entry.algorithm,
            size=entry.size,
            changed_by=user.username,
            comment="删除文件",
        )
    )
    db.commit()
    return {"id": fid, "message": "deleted"}


@router.get("/{fid}/history")
def file_history(
    fid: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    entry = db.query(FileVault).filter_by(id=fid).first()
    if entry is not None:
        ensure_group_access(db, user, entry.group_id)
    rows = (
        db.query(FileHistory)
        .filter_by(file_id=fid)
        .order_by(FileHistory.changed_at.desc())
        .all()
    )
    return [
        {
            "id": h.id,
            "action": h.action,
            "filename": h.filename,
            "algorithm": h.algorithm,
            "size": h.size,
            "changed_by": h.changed_by,
            "changed_at": h.changed_at.isoformat() if h.changed_at else None,
            "comment": h.comment,
        }
        for h in rows
    ]
