"""首次启动的初始化：建表、创建管理员、生成加解密密钥、默认分组。

兼容旧库：db.init_db 内部会做增量加列迁移，已有数据不会丢失。
"""
from .crypto import manager
from .db import SessionLocal, init_db
from .config import ADMIN_USERNAME, ADMIN_PASSWORD, DEFAULT_GROUP_NAME
from .models import Group, User, user_groups
from .security import hash_password


def seed():
    init_db()
    db = SessionLocal()
    try:
        # 管理员账号（带 is_admin 标记）
        admin = db.query(User).filter_by(username=ADMIN_USERNAME).first()
        if admin is None:
            admin = User(
                username=ADMIN_USERNAME,
                hashed_password=hash_password(ADMIN_PASSWORD),
                is_admin=True,
            )
            db.add(admin)
            db.commit()
        elif not admin.is_admin:
            admin.is_admin = True
            db.commit()

        # 默认分组，保证系统始终至少有一个分组可绑定数据
        group = db.query(Group).filter_by(name=DEFAULT_GROUP_NAME).first()
        if group is None:
            group = Group(name=DEFAULT_GROUP_NAME, description="系统默认分组")
            db.add(group)
            db.commit()
            db.refresh(group)

        # 管理员加入默认分组（便于以管理员身份直接创建数据）
        already = db.execute(
            user_groups.select().where(
                user_groups.c.user_id == admin.id,
                user_groups.c.group_id == group.id,
            )
        ).first()
        if not already:
            db.execute(
                user_groups.insert().values(user_id=admin.id, group_id=group.id)
            )
            db.commit()

        # 兼容旧库：把没有分组的存量数据（group_id 为 NULL）归到默认分组，
        # 避免升级后这些记录对普通用户“消失”。
        from .models import FileVault, History, PasswordEntry, FileHistory

        for tbl in (PasswordEntry, FileVault, History, FileHistory):
            db.query(tbl).filter_by(group_id=None).update(
                {tbl.group_id: group.id}, synchronize_session=False
            )
        db.commit()

        manager.ensure_keys(db)
    finally:
        db.close()
