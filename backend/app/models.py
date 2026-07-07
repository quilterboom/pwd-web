from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import relationship

from .db import Base


def _utcnow():
    return datetime.now(timezone.utc)


# 用户 <-> 分组 多对多关联表
user_groups = Table(
    "user_groups",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=_utcnow)

    groups = relationship("Group", secondary=user_groups, back_populates="members")


class Group(Base):
    """分组：数据（密码 / 文件）按分组绑定，用户仅能查看所属分组的数据。"""

    __tablename__ = "groups"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(String(255), default="")
    created_at = Column(DateTime, default=_utcnow)

    members = relationship("User", secondary=user_groups, back_populates="groups")


class KeyRecord(Base):
    """服务端持有的加解密密钥对。algorithm 取值 'gpg' 或 'sm2'。"""

    __tablename__ = "keys"

    id = Column(Integer, primary_key=True)
    algorithm = Column(String(16), unique=True, nullable=False, index=True)
    public_key = Column(Text, nullable=False)
    private_key = Column(Text, nullable=False)
    created_at = Column(DateTime, default=_utcnow)


class OrgKey(Base):
    """组织级密钥库：每个分组可保存多对命名密钥（公钥 + 可选私钥）。

    用于在团队/部门内部分发加密用的公钥，或导入外部公钥做共享加密。
    私钥字段允许为空（仅公钥条目常用于「只需对方能解密但本地不持有私钥」的场景）。
    """

    __tablename__ = "org_keys"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), index=True, nullable=False)
    name = Column(String(128), nullable=False)  # 用户起的名字，例如 "研发中心 GPG 主密钥"
    algorithm = Column(String(16), nullable=False)  # 'gpg' | 'sm2'
    public_key = Column(Text, nullable=False)
    private_key = Column(Text, nullable=True)
    fingerprint = Column(String(64), default="")  # 指纹/标识，方便识别密钥
    has_private = Column(Boolean, nullable=False, default=False)  # 是否存有私钥（便于前端显示）
    created_by = Column(String(64), default="")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class PasswordEntry(Base):
    __tablename__ = "passwords"

    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=True, default="")  # 已取消强制标题；保留字段以便审计/兼容旧记录
    username = Column(String(255), default="")
    # algorithm: 'gpg' | 'sm2' 为 legacy 方案，'symmetric' 为每条独立密码加密
    algorithm = Column(String(16), nullable=False, default="symmetric")
    # scheme: 'legacy' = legacy 方案（兼容旧数据）；
    #         'entry'  = 每条密码用自己的「条目密码」对称加密（服务端不持有密钥，查看/修改必须输密码）
    scheme = Column(String(16), default="legacy")
    ciphertext = Column(Text, nullable=False)  # legacy: gpg armored / sm2 base64；entry: SM4-CBC 十六进制密文
    entry_salt = Column(String(64), default="")  # entry 方案：PBKDF2-SM3 的 salt（hex）
    entry_iv = Column(String(64), default="")  # entry 方案：SM4-CBC 的 iv（hex）
    notes = Column(Text, default="")
    group_id = Column(Integer, index=True, nullable=True)  # 绑定分组
    orgkey_id = Column(Integer, ForeignKey("org_keys.id", ondelete="SET NULL"), index=True, nullable=True)  # legacy 方案使用的 OrgKey（选用，不填则用服务端 KeyRecord）
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    created_by = Column(String(64), default="")
    updated_by = Column(String(64), default="")
    deleted = Column(Boolean, default=False)


class History(Base):
    """修改记录（审计日志）。仅保存加密后的密文快照，绝不落库明文。"""

    __tablename__ = "history"

    id = Column(Integer, primary_key=True)
    password_id = Column(Integer, index=True)
    group_id = Column(Integer, index=True, nullable=True)
    action = Column(String(16), nullable=False)  # create | update | delete
    title = Column(String(255))
    username = Column(String(255))
    algorithm = Column(String(16))
    ciphertext = Column(Text)  # 该次操作时的密文快照（用于审计，不包含明文）
    notes = Column(Text)
    changed_by = Column(String(64))
    changed_at = Column(DateTime, default=_utcnow)
    comment = Column(String(255))  # 人类可读说明，如“修改了 secret,notes”


class FileVault(Base):
    """文件保险箱：服务端加密后的文件。密文落盘到 config.FILES_DIR，这里只存元数据。"""

    __tablename__ = "file_vault"

    id = Column(Integer, primary_key=True)
    filename = Column(String(512), nullable=False)  # 原始文件名（展示用）
    stored_name = Column(String(256), nullable=False)  # 落盘文件名，如 12.gpg / 12.sm2
    algorithm = Column(String(16), nullable=False)  # 'gpg' | 'sm2'
    size = Column(Integer, default=0)  # 原始文件字节数
    content_type = Column(String(128), default="application/octet-stream")
    group_id = Column(Integer, index=True, nullable=True)  # 绑定分组
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    created_by = Column(String(64), default="")
    updated_by = Column(String(64), default="")
    deleted = Column(Boolean, default=False)


class FileHistory(Base):
    """文件保险箱审计日志：记录上传 / 解密下载 / 删除等操作。"""

    __tablename__ = "file_history"

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, index=True)
    group_id = Column(Integer, index=True, nullable=True)
    action = Column(String(16), nullable=False)  # upload | decrypt | delete
    filename = Column(String(512))
    algorithm = Column(String(16))
    size = Column(Integer)
    changed_by = Column(String(64))
    changed_at = Column(DateTime, default=_utcnow)
    comment = Column(String(255))
