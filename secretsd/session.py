from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
import dbus
import dbus.service
import os

from .crypto_backend import (
    AES_BLOCK_BYTES,
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    hkdf_sha256_derive,
    pkcs7_pad,
    pkcs7_unpad,
)

MODP1024_PRIME=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff
MODP1024_GEN=2

MODP1024 = dh.DHParameterNumbers(p=MODP1024_PRIME, g=MODP1024_GEN)

class SecretServiceSession(dbus.service.Object):
    ROOT = "/org/freedesktop/secrets/session"
    PATH = "/org/freedesktop/secrets/session/s%d"

    def __init__(self, service, bus_path, algorithm):
        self.bus_path = bus_path
        self.algorithm = algorithm
        self.kex_done = False
        self.crypt_key = None
        super().__init__(service.bus, bus_path)

    def kex(self, input):
        if self.algorithm == "plain":
            return (dbus.ByteArray(b""), True)
        elif self.algorithm == "dh-ietf1024-sha256-aes128-cbc-pkcs7":
            dh_params = MODP1024.parameters(default_backend())
            our_priv = dh_params.generate_private_key()
            peer_pubn = dh.DHPublicNumbers(int.from_bytes(input, "big"),
                                           MODP1024)
            peer_pub = peer_pubn.public_key(default_backend())
            shared_key = our_priv.exchange(peer_pub)
            self.crypt_key = hkdf_sha256_derive(shared_key, 128 // 8)
            output = our_priv.public_key().public_numbers().y
            return (dbus.ByteArray(output.to_bytes(128, "big")), True)
        else:
            raise dbus.DBusException("org.freedesktop.DBus.Error.NotSupported")

    def encrypt(self, input):
        if self.algorithm == "plain":
            return input, None
        elif self.algorithm == "dh-ietf1024-sha256-aes128-cbc-pkcs7":
            key = self.crypt_key
            iv = os.urandom(AES_BLOCK_BYTES)
            ct = pkcs7_pad(input, AES_BLOCK_BYTES)
            ct = aes_cbc_encrypt(ct, key, iv)
            return ct, iv

    def decrypt(self, input, iv):
        if self.algorithm == "plain":
            return input
        elif self.algorithm == "dh-ietf1024-sha256-aes128-cbc-pkcs7":
            key = self.crypt_key
            pt = aes_cbc_decrypt(input, key, iv)
            pt = pkcs7_unpad(pt, AES_BLOCK_BYTES)
            return pt
