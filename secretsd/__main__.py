import argparse
import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import logging
import os
import sys
import xdg.BaseDirectory

os.umask(0o077)
sys.stdout.reconfigure(line_buffering=True)
logging.basicConfig(level=logging.INFO, format="%(message)s")

from .database import SecretsDatabase
from .service import SecretService

default_dir = xdg.BaseDirectory.save_data_path("nullroute.eu.org/secretsd")
default_db_path = os.path.join(default_dir, "secrets.db")
default_key_loc = "file:%s" % os.path.join(default_dir, "secrets.key")

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--db-path", metavar="PATH",
                    help="use alternative secrets.db path")
parser.add_argument("-k", "--key-location", metavar="TYPE:PATH",
                    help="specify the master key location")
args = parser.parse_args()

db_path = args.db_path or default_db_path
key_loc = args.key_location or default_key_loc

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
sdb = SecretsDatabase(db_path, key_loc)
svc = SecretService(bus, sdb)

loop = GLib.MainLoop()
loop.run()
