# This module can load passwords from external sources, such as files or
# environment variables or KWallet (and no, *not* libsecret -- as much as I
# want to use the nifty gi-based libsecret API...).
#
# It deals with strings (the lowest common denominator), but it's really meant
# to be used for storing Base64-encoded keys and not raw passwords.

import dbus
import os
import re
import subprocess

class KWalletClient():
    app_id = "org.eu.nullroute.Secretsd"
    folder = "Passwords"

    def __init__(self):
        self.bus = dbus.SessionBus()
        self.mgr = self.bus.get_object("org.kde.kwalletd5", "/modules/kwalletd5")
        self.mgr = dbus.Interface(self.mgr, "org.kde.KWallet")

    def __enter__(self):
        self.wallet = self.mgr.localWallet()
        self.handle = self.mgr.open(self.wallet, 0, self.app_id)
        return self

    def __exit__(self, *argv):
        self.mgr.disconnectApplication(self.wallet, self.app_id)

    def get_password(self, name):
        if self.mgr.hasEntry(self.handle, self.folder, name, self.app_id):
            return str(self.mgr.readPassword(self.handle, self.folder, name, self.app_id))
        else:
            raise KeyError(name)

    def set_password(self, name, value):
        self.mgr.writePassword(self.handle, self.folder, name, value, self.app_id)

def _parse_specifier(source):
    m = re.match(r"^(\w+):(.*)", source)
    if m:
        return m.groups()
    else:
        # Too easy to end up saving keys in a file named 'kwallet'...
        #return "file", source
        raise ValueError("key location must be specified as 'type:rest'")

def load_ext_key(source):
    kind, rest = _parse_specifier(source)
    if kind == "env":
        return os.environ[rest]
    elif kind == "exec":
        env = {**os.environb, "ACTION": "load"}
        res = subprocess.run(rest, shell=True,
                                   env=env,
                                   stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE,
                                   check=True)
        return res.stdout.decode().strip()
    elif kind == "file":
        with open(rest, "r") as fh:
            return fh.read().strip()
    elif kind == "kwallet":
        with KWalletClient() as kw:
            return kw.get_password(rest or "secretsd master key")
    elif kind == "libsecret":
        raise ValueError("cannot load external key from myself")
    else:
        raise ValueError("unknown external key source %r" % kind)

def store_ext_key(source, key):
    kind, rest = _parse_specifier(source)
    if kind == "env":
        raise ValueError("environment is volatile storage, cannot store keys there")
    elif kind == "exec":
        env = {**os.environb, "ACTION": "store"}
        res = subprocess.run(rest, shell=True,
                                   env=env,
                                   input=key.encode(),
                                   stdout=subprocess.DEVNULL,
                                   check=True)
    elif kind == "file":
        with open(rest, "w", opener=lambda p, f: os.open(p, f, 0o400)) as fh:
            fh.write(key)
    elif kind == "kwallet":
        with KWalletClient() as kw:
            kw.set_password(rest or "secretsd master key", key)
    elif kind == "libsecret":
        raise ValueError("cannot store external key in myself")
    else:
        raise ValueError("unknown external key source %r" % kind)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("specifier")
    parser.add_argument("--store-key", metavar="KEY", help="store the specified key (as text)")
    args = parser.parse_args()

    arg = args.specifier
    if key := args.store_key:
        print(f"Storing key {key!r} to {arg!r}")
        store_ext_key(arg, key)
    print(f"Retrieving key from {arg!r}")
    key = load_ext_key(arg)
    print(f"The key is {key!r}")
