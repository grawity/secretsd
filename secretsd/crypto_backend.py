import os

__all__ = [
    "AES_BLOCK_BYTES",
    "aes_cbc_encrypt",
    "aes_cbc_decrypt",
    "aes_cfb8_encrypt",
    "aes_cfb8_decrypt",
    "dh_modp1024_exchange",
    "hkdf_sha256_derive",
    "pkcs7_pad",
    "pkcs7_unpad",
]

MODP1024_PRIME = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff
MODP1024_GENERATOR = 2

backend = os.environ.get("CRYPTO_BACKEND", "cryptography")

if backend == "cryptodome":
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import HKDF
    from Crypto.Random.random import randint
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

    def dh_modp1024_exchange(peer_pubkey):
        prime = MODP1024_PRIME
        generator = MODP1024_GENERATOR
        peer_pubkey = int.from_bytes(peer_pubkey, "big")
        our_privkey = randint(1, prime-1)
        our_pubkey = pow(generator, our_privkey, prime)
        shared_key = pow(peer_pubkey, our_privkey, prime)
        our_pubkey = our_pubkey.to_bytes(1024 // 8, "big")
        shared_key = shared_key.to_bytes(1024 // 8, "big")
        return our_pubkey, shared_key

    def hkdf_sha256_derive(input, nbytes):
        return HKDF(input, nbytes, b"", hashmod=SHA256)

    def pkcs7_pad(data, size):
        return Padding.pad(data, size, style="pkcs7")

    def pkcs7_unpad(data, size):
        return Padding.unpad(data, size, style="pkcs7")

    print("using 'PyCryptodome' as crypto backend")

elif backend == "cryptography":
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    from cryptography.hazmat.primitives.ciphers.modes import CBC, CFB8
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.padding import PKCS7

    AES_BLOCK_BYTES = AES.block_size // 8

    MODP1024 = dh.DHParameterNumbers(p=MODP1024_PRIME, g=MODP1024_GENERATOR)

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

    def dh_modp1024_exchange(peer_pubkey):
        peer_pubkey = int.from_bytes(peer_pubkey, "big")
        peer_pubkey = dh.DHPublicNumbers(peer_pubkey, MODP1024).public_key()
        our_privkey = MODP1024.parameters().generate_private_key()
        shared_key = our_privkey.exchange(peer_pubkey)
        our_pubkey = our_privkey.public_key().public_numbers().y
        our_pubkey = our_pubkey.to_bytes(1024 // 8, "big")
        return our_pubkey, shared_key

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

    print("using 'python-cryptography' as crypto backend")

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
