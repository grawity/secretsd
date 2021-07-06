import dbus
import dbus.service
import os

from .crypto_backend import (
    AES_BLOCK_BYTES,
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    dh_modp1024_exchange,
    hkdf_sha256_derive,
    pkcs7_pad,
    pkcs7_unpad,
)

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
            output, shared_key = dh_modp1024_exchange(input)
            self.crypt_key = hkdf_sha256_derive(shared_key, 128 // 8)
            return (dbus.ByteArray(output), True)
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
