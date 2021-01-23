import dbus
import dbus.service
from .util import BusObjectWithProperties, NullObject, item_path_to_id

class SecretServiceItemFallback(dbus.service.FallbackObject, BusObjectWithProperties):
    ROOT = "/org/freedesktop/secrets/item"
    PATH = "/org/freedesktop/secrets/item/i%d"

    def __init__(self, service, bus_path=ROOT):
        self.service = service
        self.bus_path = bus_path
        super().__init__(self.service.bus, self.bus_path)

    def get_collection(self, path):
        item_id = item_path_to_id(path)
        attrs = self.service.db.get_attributes(item_id)
        if attrs is None:
            raise NoSuchObjectException(path)
        return attrs["xdg:collection"]

    def get_attributes(self, path):
        item_id = item_path_to_id(path)
        attrs = self.service.db.get_attributes(item_id)
        if attrs is None:
            raise NoSuchObjectException(path)
        attrs.setdefault("xdg:schema", "org.freedesktop.Secret.Generic")
        return attrs

    def set_attributes(self, path, value):
        item_id = item_path_to_id(path)
        if not self.service.db.item_exists(item_id):
            raise NoSuchObjectException(path)
        attrs["xdg:collection"] = self.get_collection(item_id)
        self.service.db.set_attributes(path, value)

    def get_label(self, path):
        item_id = item_path_to_id(path)
        meta = self.service.db.get_metadata(item_id)
        if not meta:
            raise NoSuchObjectException(path)
        return meta[0]

    def set_label(self, path, value):
        item_id = item_path_to_id(path)
        if not self.service.db.item_exists(item_id):
            raise NoSuchObjectException(path)
        self.service.db.set_metadata_label(item_id, value)

    def get_created(self, path):
        item_id = item_path_to_id(path)
        meta = self.service.db.get_metadata(item_id)
        if not meta:
            raise NoSuchObjectException(path)
        return dbus.UInt64(meta[1])

    def get_modified(self, path):
        item_id = item_path_to_id(path)
        meta = self.service.db.get_metadata(item_id)
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
        item_id = item_path_to_id(path)
        coll = self.get_collection(item_id)
        self.service.db.delete_item(item_id)
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
        item_id = item_path_to_id(path)
        session = self.service.path_objects[session]
        sec_data, sec_type = self.service.db.get_secret(item_id)
        sec_ct, sec_iv = session.encrypt(sec_data)
        return (session.bus_path, sec_iv, sec_ct, sec_type)

    @dbus.service.method("org.freedesktop.Secret.Item", "(oayays)", "",
                         path_keyword="path")
    def SetSecret(self, secret, path=None):
        item_id = item_path_to_id(path)
        session, sec_param, sec_ct, sec_type = secret
        session = self.service.path_objects[session]
        secret = session.decrypt(sec_ct, sec_param)
        self.service.db.set_secret(item_id, secret)
