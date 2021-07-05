import os

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

def aes_cfb8_wrap(data, key):
    iv = os.urandom(AES_BLOCK_BYTES)
    return iv + aes_cfb8_encrypt(data, key, iv)

def aes_cfb8_unwrap(data, key):
    iv = data[:AES_BLOCK_BYTES]
    data = data[AES_BLOCK_BYTES:]
    return aes_cfb8_decrypt(data, key, iv)

if __name__ == "__main__":
    key = os.urandom(16)
    data = os.urandom(14)
    print(data)
    data = aes_cfb8_wrap(data, key)
    data = aes_cfb8_unwrap(data, key)
    print(data)
