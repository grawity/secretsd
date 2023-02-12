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

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--db-path", metavar="PATH",
                    help="use alternative secrets.db path")
parser.add_argument("-k", "--key-location", metavar="TYPE:PATH",
                    help="specify the master key location")
args = parser.parse_args()

if not args.db_path:
    args.db_path = os.environ.get("SECRETSD_DIR")

if not args.db_path:
    args.db_path = os.path.join(default_dir, "secrets.db")

os.environ["SECRETSD_DIR"] = os.path.dirname(args.db_path)

if not args.key_location:
    args.key_location = os.environ.get("SECRETSD_KEY")

if not args.key_location:
    args.key_location = "file:${SECRETSD_DIR}/secrets.key"

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
sdb = SecretsDatabase(args.db_path, args.key_location)
svc = SecretService(bus, sdb)

loop = GLib.MainLoop()
loop.run()
