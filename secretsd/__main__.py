import argparse
import base64
import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import logging
import os
import xdg.BaseDirectory

from .database import SecretsDatabase
from .service import SecretService
from .encryption import generate_key
from .external_keys import load_ext_key, store_ext_key

os.umask(0o077)

parser = argparse.ArgumentParser()
parser.add_argument("-k", "--master-key", metavar="PATH")
args = parser.parse_args()

db_dir = xdg.BaseDirectory.save_data_path("nullroute.eu.org/secretsd")
db_path = os.path.join(db_dir, "secrets.db")
key_path = os.path.join(db_dir, "secrets.key")
mk_source = args.master_key or "file:%s" % key_path

try:
    mkey = base64.b64decode(load_ext_key(mk_source))
    if len(mkey) != 32:
        exit("error: Master key is not 32 bytes long")
except (KeyError, FileNotFoundError):
    # No passphrases or interactive prompts -- we're a D-Bus service!
    if os.path.exists(db_path):
        exit("error: Unable to load master key from %r" % mk_source)
    else:
        mkey = generate_key()
        store_ext_key(mk_source, base64.b64encode(mkey).decode())

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
sdb = SecretsDatabase(db_path, mkey)
svc = SecretService(bus, sdb)

loop = GLib.MainLoop()
loop.run()
