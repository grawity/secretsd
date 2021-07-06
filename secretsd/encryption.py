import base64
import hmac
import os

from .crypto_backend import (
    AES_BLOCK_BYTES,
    aes_cfb8_encrypt,
    aes_cfb8_decrypt,
)

KEY_SIZE_BYTES = 32

SHA256_HMAC_BYTES = 32

def _xor_bytes(a, b):
    assert(len(a) == len(b))
    return bytes([ax ^ bx for ax, bx in zip(a, b)])

def _fold_key(buf):
    assert(len(buf) == 32)
    return _xor_bytes(buf[:16], buf[16:])

def generate_key():
    return os.urandom(KEY_SIZE_BYTES)

def sha256_hmac(buf, key):
    return hmac.new(key, buf, digestmod="sha256").digest()

def aes_cfb8_wrap(data, key):
    iv = os.urandom(AES_BLOCK_BYTES)
    ct = aes_cfb8_encrypt(data, key, iv)
    buf = iv + ct
    return sha256_hmac(buf, key) + buf

def aes_cfb8_unwrap(buf, key):
    mac, buf = buf[:SHA256_HMAC_BYTES], buf[SHA256_HMAC_BYTES:]
    if sha256_hmac(buf, key) != mac:
        raise IOError("MAC verification failed")
    iv, ct = buf[:AES_BLOCK_BYTES], buf[AES_BLOCK_BYTES:]
    return aes_cfb8_decrypt(ct, key, iv)
