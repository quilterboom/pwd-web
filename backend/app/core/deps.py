from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Group, User, user_groups
from ..security import decode_token

bearer_scheme = HTTPBearer()


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = decode_token(creds.credentials)
        username = payload.get("sub")
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="无效或过期的令牌")

    user = db.query(User).filter_by(username=username).first()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="用户不存在")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="需要管理员权限")
    return user


def get_user_groups(db: Session, user: User) -> list[Group]:
    """返回当前用户可见的分组列表。

    - 管理员：返回全部分组（管理员可跨组查看/管理）。
    - 普通用户：仅返回其所属分组。
    """
    if user.is_admin:
        return db.query(Group).order_by(Group.name).all()
    return (
        db.query(Group)
        .join(user_groups, user_groups.c.group_id == Group.id)
        .filter(user_groups.c.user_id == user.id)
        .order_by(Group.name)
        .all()
    )


def get_user_group_ids(db: Session, user: User) -> set[int]:
    return {g.id for g in get_user_groups(db, user)}


def visibility_filter(column, user: User, group_ids: set[int]):
    """构造分组可见性过滤条件。

    管理员返回 None（不加过滤，可见全部）；
    普通用户返回 `column IN (group_ids)`（group_ids 为空则查不到任何数据）。
    """
    if user.is_admin:
        return None
    return column.in_(group_ids)


def ensure_group_access(db: Session, user: User, group_id: int | None) -> None:
    """校验用户是否有权访问某个分组（用于写入/读取该分组的数据）。

    管理员可访问任意分组；普通用户只能访问自己所属的分组。
    允许 group_id 为 None 的情况由调用方自行决定（此处仅校验归属）。
    """
    if user.is_admin:
        return
    if group_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="必须指定所属分组")
    ids = get_user_group_ids(db, user)
    if group_id not in ids:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="无权访问该分组的数据")
