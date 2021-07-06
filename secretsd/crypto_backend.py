import os

__all__ = [
    "AES_BLOCK_BYTES",
    "aes_cfb8_encrypt",
    "aes_cfb8_decrypt",
]

backend = os.environ.get("CRYPTO_BACKEND", "cryptography")

if backend == "cryptodome":
    from Crypto.Cipher import AES

    AES_BLOCK_BYTES = AES.block_size

    def aes_cfb8_encrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv).encrypt(data)

    def aes_cfb8_decrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv).decrypt(data)

elif backend == "cryptography":
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    from cryptography.hazmat.primitives.ciphers.modes import CFB8

    AES_BLOCK_BYTES = AES.block_size // 8

    def aes_cfb8_encrypt(data, key, iv):
        c = Cipher(AES(key), CFB8(iv)).encryptor()
        return c.update(data) + c.finalize()

    def aes_cfb8_decrypt(data, key, iv):
        c = Cipher(AES(key), CFB8(iv)).decryptor()
        return c.update(data) + c.finalize()

else:
    raise RuntimeError("unsupported crypto backend %r" % backend)

if __name__ == "__main__":
    iv = os.urandom(AES_BLOCK_BYTES)
    key = os.urandom(16)
    data = os.urandom(14)
    print(data)
    data = aes_cfb8_encrypt(data, key, iv)
    data = aes_cfb8_decrypt(data, key, iv)
    print(data)
