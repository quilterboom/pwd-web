from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..core.deps import get_current_user
from ..crypto import manager
from ..db import get_db
from ..models import KeyRecord, User

router = APIRouter(tags=["keys"])


@router.get("/api/keys/status")
def keys_status(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """返回当前服务端已生成的算法密钥情况。"""
    present = {r.algorithm: True for r in db.query(KeyRecord).all()}
    return {algo: present.get(algo, False) for algo in manager.SUPPORTED}
