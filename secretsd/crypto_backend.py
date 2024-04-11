import logging
import os

log = logging.getLogger(__name__)

# Second Oakley group (RFC 2409), to be used as "dh-ietf1024" in the 'Secret
# Service' API. Don't look at me. I didn't write the spec.
MODP1024_PRIME = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                     "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                     "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                     "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                     "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
                     "FFFFFFFFFFFFFFFF", 16)
MODP1024_GENERATOR = 2

backend = os.environ.get("CRYPTO_BACKEND", "cryptography")

if backend == "cryptodome":
    log.debug("using crypto backend %r", "PyCryptodome")

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

    def aes_cfb8_decrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv, segment_size=8).decrypt(data)

    def aes_cfb128_encrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv, segment_size=128).encrypt(data)

    def aes_cfb128_decrypt(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv, segment_size=128).decrypt(data)

    def dh_modp1024_exchange(peer_pubkey):
        prime = MODP1024_PRIME
        generator = MODP1024_GENERATOR
        our_privkey = randint(1, prime-1)
        our_pubkey = pow(generator, our_privkey, prime)
        shared_key = pow(peer_pubkey, our_privkey, prime)
        shared_key = shared_key.to_bytes(1024 // 8, "big")
        return our_pubkey, shared_key

    def hkdf_sha256_derive(input, nbytes):
        return HKDF(input, nbytes, b"", hashmod=SHA256)

    def pkcs7_pad(data, size):
        return Padding.pad(data, size, style="pkcs7")

    def pkcs7_unpad(data, size):
        return Padding.unpad(data, size, style="pkcs7")

elif backend == "cryptography":
    log.debug("using crypto backend %r", "python-cryptography")

    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    from cryptography.hazmat.primitives.ciphers.modes import CBC, CFB, CFB8
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.padding import PKCS7

    AES_BLOCK_BYTES = AES.block_size // 8

    def aes_cbc_encrypt(data, key, iv):
        c = Cipher(AES(key), CBC(iv)).encryptor()
        return c.update(data) + c.finalize()

    def aes_cbc_decrypt(data, key, iv):
        c = Cipher(AES(key), CBC(iv)).decryptor()
        return c.update(data) + c.finalize()

    def aes_cfb8_decrypt(data, key, iv):
        c = Cipher(AES(key), CFB8(iv)).decryptor()
        return c.update(data) + c.finalize()

    def aes_cfb128_encrypt(data, key, iv):
        c = Cipher(AES(key), CFB(iv)).encryptor()
        return c.update(data) + c.finalize()

    def aes_cfb128_decrypt(data, key, iv):
        c = Cipher(AES(key), CFB(iv)).decryptor()
        return c.update(data) + c.finalize()

    def dh_modp1024_exchange(peer_pubkey):
        group = dh.DHParameterNumbers(p=MODP1024_PRIME,
                                      g=MODP1024_GENERATOR)
        peer_pubkey = dh.DHPublicNumbers(peer_pubkey, group).public_key()
        our_privkey = group.parameters().generate_private_key()
        shared_key = our_privkey.exchange(peer_pubkey)
        our_pubkey = our_privkey.public_key().public_numbers().y
        return our_pubkey, shared_key

    def hkdf_sha256_derive(input, nbytes):
        k = HKDF(algorithm=SHA256(), length=nbytes, salt=b"", info=b"")
        return k.derive(input)

    def pkcs7_pad(data, size):
        p = PKCS7(size * 8).padder()
        return p.update(data) + p.finalize()

    def pkcs7_unpad(data, size):
        p = PKCS7(size * 8).unpadder()
        return p.update(data) + p.finalize()

else:
    raise RuntimeError("unsupported crypto backend %r" % backend)
