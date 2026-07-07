"""管理员接口：账号管理、分组管理，以及当前用户可见分组查询。

- `/api/groups/mine`：任意登录用户可获取自己所属分组（用于前端下拉选择）。
- `/api/admin/users`：仅管理员。创建/列表/修改/删除账号，并管理其所属分组。
- `/api/admin/groups`：仅管理员。创建/列表/修改/删除分组，并管理其成员。
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.deps import (
    get_current_user,
    get_user_groups,
    require_admin,
)
from ..db import get_db
from ..models import FileVault, Group, PasswordEntry, User, user_groups
from ..security import hash_password

# ---------------- 当前用户可见分组（非管理员接口） ----------------
mine_router = APIRouter(tags=["groups"])

# ---------------- 管理员：用户管理 ----------------
users_router = APIRouter(prefix="/api/admin/users", tags=["admin-users"])
# ---------------- 管理员：分组管理 ----------------
groups_router = APIRouter(prefix="/api/admin/groups", tags=["admin-groups"])


# ============================ 当前用户分组 ============================
@mine_router.get("/api/groups/mine")
def groups_mine(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    groups = get_user_groups(db, user)
    return [{"id": g.id, "name": g.name} for g in groups]


# ============================ 用户管理 ============================
class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: bool = False
    group_ids: list[int] = []


class UserUpdate(BaseModel):
    password: Optional[str] = None
    is_admin: Optional[bool] = None
    group_ids: Optional[list[int]] = None


def _user_groups_out(db: Session, user: User) -> list[dict]:
    return [{"id": g.id, "name": g.name} for g in get_user_groups(db, user)]


def _link_user_group(db: Session, user_id: int, group_id: int) -> None:
    exists = db.execute(
        user_groups.select().where(
            user_groups.c.user_id == user_id,
            user_groups.c.group_id == group_id,
        )
    ).first()
    if not exists:
        db.execute(
            user_groups.insert().values(user_id=user_id, group_id=group_id)
        )


def _unlink_user_group(db: Session, **where) -> None:
    stmt = user_groups.delete()
    for col, val in where.items():
        stmt = stmt.where(getattr(user_groups.c, col) == val)
    db.execute(stmt)


@users_router.get("")
def list_users(
    _: User = Depends(require_admin), db: Session = Depends(get_db)
):
    rows = db.query(User).order_by(User.username).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "is_admin": bool(u.is_admin),
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "groups": _user_groups_out(db, u),
        }
        for u in rows
    ]


@users_router.post("")
def create_user(
    req: UserCreate,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not req.username or not req.password:
        raise HTTPException(status_code=400, detail="用户名与密码均不能为空")
    if db.query(User).filter_by(username=req.username).first():
        raise HTTPException(status_code=409, detail="用户名已存在")

    user = User(
        username=req.username,
        hashed_password=hash_password(req.password),
        is_admin=req.is_admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    for gid in req.group_ids:
        if db.query(Group).filter_by(id=gid).first():
            _link_user_group(db, user.id, gid)
    db.commit()
    return {"id": user.id, "username": user.username, "message": "created"}


@users_router.put("/{uid}")
def update_user(
    uid: int,
    req: UserUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(id=uid).first()
    if user is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if user.id == admin.id and req.is_admin is False:
        raise HTTPException(status_code=400, detail="不能取消自己的管理员权限")

    if req.password:
        user.hashed_password = hash_password(req.password)
    if req.is_admin is not None:
        user.is_admin = req.is_admin

    if req.group_ids is not None:
        _unlink_user_group(db, user_id=user.id)
        for gid in req.group_ids:
            if db.query(Group).filter_by(id=gid).first():
                _link_user_group(db, user.id, gid)
    db.commit()
    return {"id": user.id, "username": user.username, "message": "updated"}


@users_router.delete("/{uid}")
def delete_user(
    uid: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if uid == admin.id:
        raise HTTPException(status_code=400, detail="不能删除当前登录的管理员账号")
    user = db.query(User).filter_by(id=uid).first()
    if user is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    _unlink_user_group(db, user_id=user.id)
    db.delete(user)
    db.commit()
    return {"id": uid, "message": "deleted"}


# ============================ 分组管理 ============================
class GroupCreate(BaseModel):
    name: str
    description: str = ""
    member_ids: list[int] = []


class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    member_ids: Optional[list[int]] = None


@groups_router.get("")
def list_groups(
    _: User = Depends(require_admin), db: Session = Depends(get_db)
):
    rows = db.query(Group).order_by(Group.name).all()
    out = []
    for g in rows:
        members = (
            db.query(User)
            .join(user_groups, user_groups.c.user_id == User.id)
            .filter(user_groups.c.group_id == g.id)
            .order_by(User.username)
            .all()
        )
        out.append(
            {
                "id": g.id,
                "name": g.name,
                "description": g.description,
                "created_at": g.created_at.isoformat() if g.created_at else None,
                "member_count": len(members),
                "members": [{"id": m.id, "username": m.username} for m in members],
            }
        )
    return out


@groups_router.post("")
def create_group(
    req: GroupCreate,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not req.name:
        raise HTTPException(status_code=400, detail="分组名称不能为空")
    if db.query(Group).filter_by(name=req.name).first():
        raise HTTPException(status_code=409, detail="分组名称已存在")

    group = Group(name=req.name, description=req.description)
    db.add(group)
    db.commit()
    db.refresh(group)

    for uid in req.member_ids:
        u = db.query(User).filter_by(id=uid).first()
        if u:
            _link_user_group(db, uid, group.id)
    db.commit()
    return {"id": group.id, "name": group.name, "message": "created"}


@groups_router.put("/{gid}")
def update_group(
    gid: int,
    req: GroupUpdate,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    group = db.query(Group).filter_by(id=gid).first()
    if group is None:
        raise HTTPException(status_code=404, detail="分组不存在")
    if req.name is not None and req.name != group.name:
        if db.query(Group).filter_by(name=req.name).first():
            raise HTTPException(status_code=409, detail="分组名称已存在")
        group.name = req.name
    if req.description is not None:
        group.description = req.description
    if req.member_ids is not None:
        _unlink_user_group(db, group_id=group.id)
        for uid in req.member_ids:
            if db.query(User).filter_by(id=uid).first():
                _link_user_group(db, uid, group.id)
    db.commit()
    return {"id": group.id, "name": group.name, "message": "updated"}


@groups_router.delete("/{gid}")
def delete_group(
    gid: int,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    group = db.query(Group).filter_by(id=gid).first()
    if group is None:
        raise HTTPException(status_code=404, detail="分组不存在")
    bound_pw = db.query(PasswordEntry).filter_by(group_id=gid, deleted=False).count()
    bound_file = db.query(FileVault).filter_by(group_id=gid, deleted=False).count()
    if bound_pw or bound_file:
        raise HTTPException(
            status_code=400,
            detail=f"该分组仍绑定 {bound_pw} 条密码、{bound_file} 个文件，请先迁移或删除这些数据",
        )
    _unlink_user_group(db, group_id=gid)
    db.delete(group)
    db.commit()
    return {"id": gid, "message": "deleted"}
