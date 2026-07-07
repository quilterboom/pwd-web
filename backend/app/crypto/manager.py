"""加解密提供者管理：根据算法名分发，并在首次使用时确保服务端密钥已生成。"""
from . import gpg_crypto, sm2_crypto

PROVIDERS = {
    "gpg": gpg_crypto,
    "sm2": sm2_crypto,
}

SUPPORTED = tuple(PROVIDERS.keys())


def get_provider(algorithm: str):
    if algorithm not in PROVIDERS:
        raise ValueError(f"不支持的算法: {algorithm}")
    return PROVIDERS[algorithm]


def ensure_keys(db):
    """保证 gpg / sm2 两套密钥对都已存在，缺失则自动生成并落库。"""
    from ..models import KeyRecord

    for algo in SUPPORTED:
        exists = db.query(KeyRecord).filter_by(algorithm=algo).first()
        if exists is None:
            pub, priv = PROVIDERS[algo].generate_keypair()
            db.add(KeyRecord(algorithm=algo, public_key=pub, private_key=priv))
            db.commit()


def encrypt_secret(db, algorithm: str, plaintext: str) -> str:
    from ..models import KeyRecord

    rec = db.query(KeyRecord).filter_by(algorithm=algorithm).first()
    if rec is None:
        raise RuntimeError(f"缺少 {algorithm} 算法密钥")
    return PROVIDERS[algorithm].encrypt(plaintext, rec.public_key)


def decrypt_secret(db, algorithm: str, ciphertext: str) -> str:
    from ..models import KeyRecord

    rec = db.query(KeyRecord).filter_by(algorithm=algorithm).first()
    if rec is None:
        raise RuntimeError(f"缺少 {algorithm} 算法密钥")
    return PROVIDERS[algorithm].decrypt(ciphertext, rec.private_key)


def encrypt_file(db, algorithm: str, data: bytes) -> bytes:
    """加密文件字节：GPG 用 pgpy（内部混合加密），SM2 用 gmssl（KDF，任意长度）。"""
    from ..models import KeyRecord

    rec = db.query(KeyRecord).filter_by(algorithm=algorithm).first()
    if rec is None:
        raise RuntimeError(f"缺少 {algorithm} 算法密钥")
    return PROVIDERS[algorithm].encrypt_bytes(data, rec.public_key)


def decrypt_file(db, algorithm: str, data: bytes) -> bytes:
    """解密文件字节，返回原始内容。"""
    from ..models import KeyRecord

    rec = db.query(KeyRecord).filter_by(algorithm=algorithm).first()
    if rec is None:
        raise RuntimeError(f"缺少 {algorithm} 算法密钥")
    return PROVIDERS[algorithm].decrypt_bytes(data, rec.private_key)
