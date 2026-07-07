from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..core.deps import ensure_group_access, get_current_user
from ..db import get_db
from ..models import History, PasswordEntry, User

router = APIRouter(
    prefix="/api/passwords",
    tags=["history"],
    dependencies=[Depends(get_current_user)],
)


def _serialize(r: History) -> dict:
    return {
        "id": r.id,
        "password_id": r.password_id,
        "group_id": r.group_id,
        "action": r.action,
        "title": r.title,
        "username": r.username,
        "algorithm": r.algorithm,
        "notes": r.notes,
        "changed_by": r.changed_by,
        "changed_at": r.changed_at.isoformat() if r.changed_at else None,
        "comment": r.comment,
    }


@router.get("/{pid}/history")
def get_history(
    pid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    parent = db.query(PasswordEntry).filter_by(id=pid).first()
    if parent is not None:
        # 校验当前用户对该密码所属分组是否可见，避免越权查看他人审计记录
        ensure_group_access(db, user, parent.group_id)
    rows = (
        db.query(History)
        .filter_by(password_id=pid)
        .order_by(History.changed_at.desc())
        .all()
    )
    return [_serialize(r) for r in rows]
