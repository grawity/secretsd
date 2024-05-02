import argparse
import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import logging
import logging.handlers
import os
import platformdirs
import sys

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--db-path", metavar="PATH",
                        help="specify the path to secrets.db")
    parser.add_argument("-k", "--key-location", metavar="TYPE:PATH",
                        help="specify the master key location")
    parser.add_argument("-F", "--no-syslog", action="store_true",
                        help="log to stderr rather than syslog")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="enable detailed logging")
    args = parser.parse_args()

    # Set up logging

    log_level = [logging.INFO, logging.DEBUG][args.verbose]
    if not (args.no_syslog or sys.stderr.isatty()):
        log_handler = logging.handlers.SysLogHandler(address="/dev/log")
        log_format = "secretsd: %(message)s"
    else:
        log_handler = logging.StreamHandler()
        log_format = "%(message)s"

    logging.basicConfig(handlers=[log_handler],
                        level=log_level,
                        format=log_format)

    # Determine file locations

    default_dir = platformdirs.user_data_path("nullroute.eu.org/secretsd")
    if not os.path.exists(default_dir):
        default_dir = platformdirs.user_data_path("nullroute.lt/secretsd")

    if not args.db_path:
        args.db_path = os.environ.get("SECRETSD_DIR")
    if not args.db_path:
        args.db_path = os.path.join(default_dir, "secrets.db")

    os.environ["SECRETSD_DIR"] = os.path.dirname(args.db_path)

    if not args.key_location:
        args.key_location = os.environ.get("SECRETSD_KEY")
    if not args.key_location:
        args.key_location = "file:${SECRETSD_DIR}/secrets.key"

    # Set up other environment

    os.umask(0o077)
    os.chdir(os.path.dirname(args.db_path))

    if sys.platform == "linux":
        try:
            import prctl
        except ImportError:
            logging.debug("failed to import prctl; core dumps remain enabled")
        else:
            logging.debug("using prctl.set_dumpable() to disable core dumps")
            prctl.set_dumpable(False)

    # Import components after logging is set up

    from .database import SecretsDatabase
    from .service import SecretService

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    sdb = SecretsDatabase(args.db_path, args.key_location)
    svc = SecretService(bus, sdb) # noqa: F841 -- automatically exported via dbus

    logging.debug("starting main loop")

    loop = GLib.MainLoop()
    loop.run()

if __name__ == "__main__":
    run()
