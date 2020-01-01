import dbus
import dbus.service
from .exception import NoSuchObjectException
from .util import BusObjectWithProperties, NullObject

class SecretServiceCollectionFallback(dbus.service.FallbackObject, BusObjectWithProperties):
    ROOT = "/org/freedesktop/secrets/collection"
    PATH = "/org/freedesktop/secrets/collection/c%d"

    def __init__(self, service, bus_path=ROOT):
        self.service = service
        self.bus_path = bus_path
        super().__init__(self.service.bus, self.bus_path)

    def resolve_path(self, path):
        if path.startswith("/org/freedesktop/secrets/aliases/"):
            orig = path
            alias = path[len("/org/freedesktop/secrets/aliases/"):]
            path = self.service.db.resolve_alias(alias)
            if not path:
                raise NoSuchObjectException(orig)
        if not self.service.db.collection_exists(path):
            raise NoSuchObjectException(path)
        return path

    def get_items(self, path):
        path = self.resolve_path(path)
        items = self.service.db.find_items({"xdg:collection": path})
        return dbus.Array(items, "o")

    def get_label(self, path):
        path = self.resolve_path(path)
        meta = self.service.db.get_collection_metadata(path)
        return dbus.String(meta[0])

    def set_label(self, path, value):
        path = self.resolve_path(path)
        label = str(value)
        self.service.db.set_collection_metadata_label(path, label)

    def get_created(self, path):
        path = self.resolve_path(path)
        meta = self.service.db.get_collection_metadata(path)
        return dbus.UInt64(meta[1])

    def get_modified(self, path):
        path = self.resolve_path(path)
        meta = self.service.db.get_collection_metadata(path)
        return dbus.UInt64(meta[2])

    INTERFACE = "org.freedesktop.Secret.Collection"
    PROPERTIES = {
        "Items":        (get_items,     None,       dbus.Array([], "o")),
        "Label":        (get_label,     set_label,  dbus.String("")),
        "Locked":       (None,          None,       dbus.Boolean(False)),
        "Created":      (get_created,   None,       dbus.UInt64(0)),
        "Modified":     (get_modified,  None,       dbus.UInt64(0)),
    }

    @dbus.service.method("org.freedesktop.Secret.Collection", "a{sv}(oayays)b", "oo",
                         sender_keyword="sender", path_keyword="path", byte_arrays=True)
    def CreateItem(self, properties, secret, replace,
                   sender=None, path=None):
        path = self.resolve_path(path)
        label = properties["org.freedesktop.Secret.Item.Label"]
        attrs = properties["org.freedesktop.Secret.Item.Attributes"]

        attrs.setdefault("xdg:collection", path)
        attrs.setdefault("xdg:schema", "org.freedesktop.Secret.Generic")

        sec_session, sec_param, sec_ct, sec_type = secret
        sec_session = self.service.path_objects[sec_session]
        sec_data = sec_session.decrypt(sec_ct, sec_param)

        existing = self.service.db.find_items(attrs) if replace else []
        if existing:
            bus_path = existing[0]
            self.service.db.set_attributes(bus_path, attrs)
            self.service.db.set_secret(bus_path, sec_data, sec_type)
            self.ItemChanged(bus_path)
        else:
            bus_path = self.service.make_bus_path(True, SecretServiceItemFallback)
            self.service.db.add_item(bus_path, label, attrs, sec_data, sec_type)
            self.ItemCreated(bus_path)
            self.PropertiesChanged("org.freedesktop.Secret.Collection",
                                   {"Items": self.get_items()},
                                   [])

        return (dbus.ObjectPath(bus_path), NullObject)

    @dbus.service.method("org.freedesktop.Secret.Collection", "", "o",
                         path_keyword="path")
    def Delete(self, path=None):
        path = self.resolve_path(path)
        self.service.db.delete_collection(path)
        self.service.CollectionDeleted(path)
        self.service.PropertiesChanged("org.freedesktop.Secret.Service",
                                       {"Collections": self.service.get_collections()},
                                       [])
        return NullObject

    @dbus.service.method("org.freedesktop.Secret.Collection", "a{ss}", "ao",
                         path_keyword="path")
    def SearchItems(self, attributes, path=None):
        path = self.resolve_path(path)
        attributes["xdg:collection"] = path
        items = self.service.db.find_items(attributes)
        return (items, [])

    @dbus.service.signal("org.freedesktop.Secret.Collection", "o")
    def ItemChanged(self, bus_path):
        pass

    @dbus.service.signal("org.freedesktop.Secret.Collection", "o")
    def ItemCreated(self, bus_path):
        pass

    @dbus.service.signal("org.freedesktop.Secret.Collection", "o")
    def ItemDeleted(self, bus_path):
        pass
