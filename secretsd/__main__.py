import argparse
import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import logging
import os
import xdg.BaseDirectory

from .database import SecretsDatabase
from .service import SecretService

os.umask(0o077)

parser = argparse.ArgumentParser()
parser.add_argument("-k", "--master-key", metavar="PATH")
args = parser.parse_args()

db_dir = xdg.BaseDirectory.save_data_path("nullroute.eu.org/secretsd")
db_path = os.path.join(db_dir, "secrets.db")
key_path = os.path.join(db_dir, "secrets.key")
key_path = args.master_key or "file:%s" % key_path

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
sdb = SecretsDatabase(db_path, key_path)
svc = SecretService(bus, sdb)

loop = GLib.MainLoop()
loop.run()
