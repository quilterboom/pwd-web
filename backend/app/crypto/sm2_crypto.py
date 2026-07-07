"""SM2 加密封装（基于 gmssl）。

gmssl 的 CryptSM2 不会自动由私钥推导公钥，这里用其内部 _kg 完成 Q = priv * G。
加密结果为字节，对外统一用 base64 文本存储。
"""
import base64

from gmssl import func, sm2


def generate_keypair():
    """生成 SM2 密钥对，返回 (公钥 hex(128位), 私钥 hex(64位))。"""
    priv = func.random_hex(64)
    c = sm2.CryptSM2(public_key="", private_key=priv)
    pub = c._kg(int(priv, 16), c.ecc_table["g"])  # Q = priv * G
    return pub, priv


def encrypt(plaintext: str, public_key_hex: str) -> str:
    c = sm2.CryptSM2(public_key=public_key_hex, private_key="")
    ciphertext = c.encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt(ciphertext_b64: str, private_key_hex: str) -> str:
    c = sm2.CryptSM2(public_key="", private_key=private_key_hex)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = c.decrypt(ciphertext)
    return plaintext.decode("utf-8")


def encrypt_bytes(data: bytes, public_key_hex: str) -> bytes:
    """加密任意二进制数据（文件）。SM2 基于 KDF（ECIES 思路），支持任意长度。"""
    c = sm2.CryptSM2(public_key=public_key_hex, private_key="")
    return c.encrypt(data)


def decrypt_bytes(ciphertext: bytes, private_key_hex: str) -> bytes:
    """解密文件密文，返回原始字节。"""
    c = sm2.CryptSM2(public_key="", private_key=private_key_hex)
    return bytes(c.decrypt(ciphertext))
