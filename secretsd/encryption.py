import base64
import hmac
import os

from .crypto_backend import *

KEY_SIZE_BYTES = 32

SHA256_HMAC_BYTES = 32

def generate_key():
    # Always generate 256-bit keys for simplicity; AES-128 can just fold them in half.
    return os.urandom(KEY_SIZE_BYTES)

def _xor_bytes(a, b):
    assert(len(a) == len(b))
    return bytes([ax ^ bx for ax, bx in zip(a, b)])

def _fold_key(buf):
    assert(len(buf) == 32)
    return _xor_bytes(buf[:16], buf[16:])

def sha256_hmac(buf, key):
    return hmac.new(key, buf, digestmod="sha256").digest()

def aes_cfb8_wrap(data, key):
    mac = sha256_hmac(data, key)
    iv = os.urandom(AES_BLOCK_BYTES)
    return mac + iv + aes_cfb8_encrypt(data, key, iv)

def aes_cfb8_unwrap(buf, key):
    mac, buf = buf[:SHA256_HMAC_BYTES], buf[SHA256_HMAC_BYTES:]
    iv, buf = buf[:AES_BLOCK_BYTES], buf[AES_BLOCK_BYTES:]
    data = aes_cfb8_decrypt(buf, key, iv)
    if sha256_hmac(data, key) != mac:
        raise IOError("MAC verification failed")
    return data

if __name__ == "__main__":
    key = os.urandom(16)
    data = os.urandom(14)
    print(data)
    data = aes_cfb8_wrap(data, key)
    data = aes_cfb8_unwrap(data, key)
    print(data)
