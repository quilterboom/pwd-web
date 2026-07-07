"""密码条目级对称加密：每条密码用自己的「条目密码」加密，服务端不持有密钥。

设计参考 D:\\aicode\\passwdpm（PassPy）的新增密码对称加密逻辑：
- 密钥派生：PBKDF2-SM3（纯 gmssl.sm3 实现，与 PassPy 的 _sm2_derive_key 一致）
- 对称加密：SM4-CBC（与 PassPy 的 sm2_encrypt_key_file 一致）

明文加密前附加 4 字节 magic 标记，解密后校验；密码错误时 SM4 解出乱码，
magic 不匹配即判定为密码错误，避免返回垃圾明文。

加解密均在服务端执行（密码由客户端通过 HTTPS 传入），符合本项目
「加解密在服务端完成」的整体定位；但服务端仅持有 salt/iv/密文，
没有条目密码就无法还原明文（零知识）。
"""
import os

from gmssl import sm3, sm4

MAGIC = b"PWM1"  # 4 字节密文前缀，用于校验密码是否正确
ITERATIONS = 10000
DK_LEN = 32  # SM4 密钥长度（字节）
BLOCK = 16  # SM4 分组长度


class WrongPasswordError(ValueError):
    """条目密码错误，无法解密。"""


def _hex_xor(a: str, b: str) -> str:
    """等长十六进制串按位异或，返回十六进制串。"""
    return "".join(format(int(a[i], 16) ^ int(b[i], 16), "x") for i in range(len(a)))


def _pbkdf2_sm3(password: str, salt: bytes, dk_len: int = DK_LEN, iterations: int = ITERATIONS) -> bytes:
    """PBKDF2-SM3 派生密钥（移植自 PassPy 的 _sm2_derive_key）。

    注意 gmssl 未提供 PBKDF2，这里用 sm3.sm3_hash 手动实现，
    与 PassPy 完全一致的逐块异或逻辑，保证跨端兼容。
    """
    password_bytes = password.encode("utf-8")
    result = []
    block = 1
    while len(b"".join(result)) < dk_len:
        u = sm3.sm3_hash(bytearray(password_bytes + salt + block.to_bytes(4, "big")))
        block_result = u
        for _ in range(2, iterations + 1):
            u = sm3.sm3_hash(bytearray(u.encode("utf-8")))
            block_result = _hex_xor(block_result, u)
        result.append(bytes.fromhex(block_result))
        block += 1
    return b"".join(result)[:dk_len]


def _pkcs7_pad(data: bytes, block_size: int = BLOCK) -> bytes:
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise WrongPasswordError("密文为空")
    pad = data[-1]
    if pad < 1 or pad > BLOCK:
        raise WrongPasswordError("填充非法")
    return data[:-pad]


def encrypt_entry(plaintext: str, password: str) -> dict:
    """用条目密码加密明文，返回 {salt, iv, ciphertext}（均为十六进制字符串）。"""
    salt = os.urandom(16)
    key = _pbkdf2_sm3(password, salt)
    iv = os.urandom(16)
    pt = _pkcs7_pad(MAGIC + plaintext.encode("utf-8"))
    crypt = sm4.CryptSM4()
    crypt.set_key(key, sm4.SM4_ENCRYPT)
    ct = crypt.crypt_cbc(iv, pt)
    return {
        "salt": salt.hex(),
        "iv": iv.hex(),
        "ciphertext": ct.hex() if isinstance(ct, bytes) else bytes(ct).hex(),
    }


def decrypt_entry(payload: dict, password: str) -> str:
    """用条目密码解密，返回明文；密码错误抛 WrongPasswordError。"""
    try:
        salt = bytes.fromhex(payload["salt"])
        iv = bytes.fromhex(payload["iv"])
        ct = bytes.fromhex(payload["ciphertext"])
    except (KeyError, ValueError) as e:
        raise WrongPasswordError("密文格式损坏") from e

    key = _pbkdf2_sm3(password, salt)
    crypt = sm4.CryptSM4()
    crypt.set_key(key, sm4.SM4_DECRYPT)
    try:
        pt = crypt.crypt_cbc(iv, ct)
    except Exception as e:  # 解密本身出错（如长度非块倍数）
        raise WrongPasswordError("解密失败") from e
    if isinstance(pt, bytearray):
        pt = bytes(pt)
    elif isinstance(pt, str):
        pt = pt.encode("latin-1")
    try:
        pt = _pkcs7_unpad(pt)
    except WrongPasswordError:
        raise
    except Exception as e:
        raise WrongPasswordError("解密失败") from e

    if not pt.startswith(MAGIC):
        raise WrongPasswordError("密码错误，无法解密该条目")
    return pt[len(MAGIC):].decode("utf-8")
