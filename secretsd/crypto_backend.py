import os

__all__ = [
    "AES_BLOCK_BYTES",
    "aes_cbc_encrypt",
    "aes_cbc_decrypt",
    "aes_cfb8_encrypt",
    "aes_cfb8_decrypt",
    "hkdf_sha256_derive",
    "pkcs7_pad",
    "pkcs7_unpad",
]

backend = os.environ.get("CRYPTO_BACKEND", "cryptography")

if backend == "cryptodome":
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import HKDF
    from Crypto.Util import Padding

    AES_BLOCK_BYTES = AES.block_size

    def aes_cbc_encrypt(data, key, iv):
        return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

    def aes_cbc_decrypt(data, key, iv):
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

    def aes_cfb8_encrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv).encrypt(data)

    def aes_cfb8_decrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv).decrypt(data)

    def hkdf_sha256_derive(input, nbytes):
        return HKDF(input, nbytes, b"", hashmod=SHA256)

    def pkcs7_pad(data, size):
        return Padding.pad(data, size, style="pkcs7")

    def pkcs7_unpad(data, size):
        return Padding.unpad(data, size, style="pkcs7")

elif backend == "cryptography":
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    from cryptography.hazmat.primitives.ciphers.modes import CBC, CFB8
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.padding import PKCS7

    AES_BLOCK_BYTES = AES.block_size // 8

    def aes_cfb8_encrypt(data, key, iv):
        c = Cipher(AES(key), CFB8(iv)).encryptor()
        return c.update(data) + c.finalize()

    def aes_cfb8_decrypt(data, key, iv):
        c = Cipher(AES(key), CFB8(iv)).decryptor()
        return c.update(data) + c.finalize()

    def aes_cbc_encrypt(data, key, iv):
        c = Cipher(AES(key), CBC(iv)).encryptor()
        return c.update(data) + c.finalize()

    def aes_cbc_decrypt(data, key, iv):
        c = Cipher(AES(key), CBC(iv)).decryptor()
        return c.update(data) + c.finalize()

    def hkdf_sha256_derive(input, nbytes):
        k = HKDF(algorithm=SHA256(),
                 length=nbytes,
                 salt=b"",
                 info=b"")
        return k.derive(input)

    def pkcs7_pad(data, size):
        p = PKCS7(size * 8).padder()
        return p.update(data) + p.finalize()

    def pkcs7_unpad(data, size):
        p = PKCS7(size * 8).unpadder()
        return p.update(data) + p.finalize()

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
