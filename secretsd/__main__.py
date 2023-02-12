import argparse
import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import logging
import os
import sys
import xdg.BaseDirectory

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--db-path", metavar="PATH",
                    help="specify the path to secrets.db")
parser.add_argument("-k", "--key-location", metavar="TYPE:PATH",
                    help="specify the master key location")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="enable detailed logging")
args = parser.parse_args()

logging.basicConfig(level=[logging.INFO, logging.DEBUG][args.verbose],
                    format="%(message)s")

default_dir = xdg.BaseDirectory.save_data_path("nullroute.eu.org/secretsd")
if not os.path.exists(default_dir):
    default_dir = xdg.BaseDirectory.save_data_path("nullroute.lt/secretsd")

if not args.db_path:
    args.db_path = os.environ.get("SECRETSD_DIR")
if not args.db_path:
    args.db_path = os.path.join(default_dir, "secrets.db")

os.umask(0o077)
os.chdir(os.path.dirname(args.db_path))
os.environ["SECRETSD_DIR"] = os.path.dirname(args.db_path)

if not args.key_location:
    args.key_location = os.environ.get("SECRETSD_KEY")
if not args.key_location:
    args.key_location = "file:${SECRETSD_DIR}/secrets.key"

from .database import SecretsDatabase
from .service import SecretService

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
sdb = SecretsDatabase(args.db_path, args.key_location)
svc = SecretService(bus, sdb)

loop = GLib.MainLoop()
loop.run()
