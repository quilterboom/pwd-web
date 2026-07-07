"""GPG / OpenPGP 加密封装（基于纯 Python 的 pgpy）。

注意：pgpy 依赖标准库 imghdr，而该模块在 Python 3.13 中被移除，
因此在导入 pgpy 之前需要打一个最小化的 imghdr 兼容垫片。
"""
import sys
import types

if "imghdr" not in sys.modules:
    _imghdr = types.ModuleType("imghdr")
    _imghdr.what = lambda file, h=None: None  # noqa: E731
    sys.modules["imghdr"] = _imghdr

import pgpy
from pgpy.constants import (
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)


def generate_keypair():
    """生成 RSA-2048 的 GPG 密钥对，返回 (公钥 armored, 私钥 armored)。"""
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("passwdpm", email="pm@localhost")
    key.add_uid(
        uid,
        usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
    )
    return str(key.pubkey), str(key)


def encrypt(plaintext: str, public_key_armored: str) -> str:
    pub = pgpy.PGPKey.from_blob(public_key_armored)[0]
    message = pub.encrypt(pgpy.PGPMessage.new(plaintext))
    return str(message)


def decrypt(ciphertext_armored: str, private_key_armored: str) -> str:
    priv = pgpy.PGPKey.from_blob(private_key_armored)[0]
    message = pgpy.PGPMessage.from_blob(ciphertext_armored)
    return priv.decrypt(message).message


def encrypt_bytes(data: bytes, public_key_armored: str) -> bytes:
    """加密任意二进制数据（文件），返回 armored 文本的字节形式。

    pgpy 的 PGPMessage 原生支持二进制，内部已采用混合加密（会话密钥 + 公钥封装），
    与参考项目 PassPy 的文件加密过程一致，密文长度与文件大小基本无关。
    """
    pub = pgpy.PGPKey.from_blob(public_key_armored)[0]
    message = pub.encrypt(pgpy.PGPMessage.new(data))
    return str(message).encode("utf-8")


def decrypt_bytes(ciphertext: bytes, private_key_armored: str) -> bytes:
    """解密文件密文，返回原始字节。"""
    priv = pgpy.PGPKey.from_blob(private_key_armored)[0]
    message = pgpy.PGPMessage.from_blob(ciphertext.decode("utf-8"))
    return bytes(priv.decrypt(message).message)
