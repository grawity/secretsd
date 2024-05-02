import dbus
import dbus.service
import logging

from .exception import NoSuchObjectException
from .util import BusObjectWithProperties, NullObject

log = logging.getLogger(__name__)

class SecretServiceItemFallback(dbus.service.FallbackObject, BusObjectWithProperties):
    ROOT = "/org/freedesktop/secrets/item"
    PATH = "/org/freedesktop/secrets/item/i%d"

    def __init__(self, service, bus_path=ROOT):
        self.service = service
        self.bus_path = bus_path
        super().__init__(self.service.bus, self.bus_path)

    def get_collection(self, path):
        attrs = self.service.db.get_item_attributes(path)
        if attrs is None:
            raise NoSuchObjectException(path)
        return attrs["xdg:collection"]

    def get_attributes(self, path):
        attrs = self.service.db.get_item_attributes(path)
        if attrs is None:
            raise NoSuchObjectException(path)
        attrs.setdefault("xdg:schema", "org.freedesktop.Secret.Generic")
        return attrs

    def set_attributes(self, path, value):
        if not self.service.db.item_exists(path):
            raise NoSuchObjectException(path)
        attrs["xdg:collection"] = self.get_collection(path)
        self.service.db.set_item_attributes(path, value)

    def get_label(self, path):
        meta = self.service.db.get_item_metadata(path)
        if not meta:
            raise NoSuchObjectException(path)
        return meta[0]

    def set_label(self, path, value):
        if not self.service.db.item_exists(path):
            raise NoSuchObjectException(path)
        self.service.db.set_item_label(path, value)

    def get_created(self, path):
        meta = self.service.db.get_item_metadata(path)
        if not meta:
            raise NoSuchObjectException(path)
        return dbus.UInt64(meta[1])

    def get_modified(self, path):
        meta = self.service.db.get_item_metadata(path)
        if not meta:
            raise NoSuchObjectException(path)
        return dbus.UInt64(meta[2])

    INTERFACE = "org.freedesktop.Secret.Item"
    PROPERTIES = {
        "Attributes":   (get_attributes,    set_attributes, None),
        "Created":      (get_created,       None,           None),
        "Label":        (get_label,         set_label,      None),
        "Locked":       (None,              None,           False),
        "Modified":     (get_modified,      None,           None),
    }

    @dbus.service.method("org.freedesktop.Secret.Item", "", "o",
                         path_keyword="path")
    def Delete(self, path=None):
        coll = self.get_collection(path)
        self.service.db.delete_item(path)
        self.service.send_signal(coll, "org.freedesktop.Secret.Collection",
                                       "ItemDeleted",
                                       "o",
                                       path)
        self.service.send_signal(coll, "org.freedesktop.DBus.Properties",
                                       "PropertiesChanged",
                                       "sa{sv}as",
                                       "org.freedesktop.Secret.Collection",
                                       {"Items": self.service.fallback_collection.get_items(coll)},
                                       [])
        return NullObject

    @dbus.service.method("org.freedesktop.Secret.Item", "o", "(oayays)",
                         path_keyword="path")
    def GetSecret(self, session, path=None):
        session = self.service.path_objects[session]
        sec_data, sec_type = self.service.db.get_secret(path)
        sec_ct, sec_iv = session.encrypt(sec_data)
        return (session.bus_path, sec_iv, sec_ct, sec_type)

    @dbus.service.method("org.freedesktop.Secret.Item", "(oayays)", "",
                         path_keyword="path")
    def SetSecret(self, secret, path=None):
        session, sec_param, sec_ct, sec_type = secret
        session = self.service.path_objects[session]
        secret = session.decrypt(sec_ct, sec_param)
        self.service.db.set_secret(path, secret)
