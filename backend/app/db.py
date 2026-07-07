from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

from .config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    # 导入模型以确保表被注册到 Base.metadata
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _migrate_columns()


def _migrate_columns():
    """对已在运行的旧库做增量加列，避免离线服务器已有数据丢失。

    只新增缺失的列/表，绝不删除或重命名，保证向后兼容。
    """
    insp = inspect(engine)
    existing = {t: {c["name"] for c in insp.get_columns(t)} for t in insp.get_table_names()}

    # 需要追加的列： (表名, 列名, 声明)。声明需带 SQLite 兼容的默认值。
    alterations = [
        ("users", "is_admin", "INTEGER NOT NULL DEFAULT 0"),
        ("passwords", "group_id", "INTEGER"),
        ("file_vault", "group_id", "INTEGER"),
        ("history", "group_id", "INTEGER"),
        ("file_history", "group_id", "INTEGER"),
        # 条目级密码加密（每条密码用自己的密码对称加密）
        ("passwords", "scheme", "VARCHAR(16) DEFAULT 'legacy'"),
        ("passwords", "entry_salt", "VARCHAR(64) DEFAULT ''"),
        ("passwords", "entry_iv", "VARCHAR(64) DEFAULT ''"),
        # legacy 方案可选指定 OrgKey（按组织持有密钥对加密，而不是服务端默认密钥）
        ("passwords", "orgkey_id", "INTEGER"),
    ]
    with engine.begin() as conn:
        for table, col, decl in alterations:
            if table in existing and col not in existing[table]:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {decl}"))
