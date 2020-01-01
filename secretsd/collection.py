import dbus
import dbus.service
from .util import BusObjectWithProperties, NullObject

class SecretServiceCollection(dbus.service.Object, BusObjectWithProperties):
    SUPPORTS_MULTIPLE_OBJECT_PATHS = True

    PATH = "/org/freedesktop/secrets/collection/c%d"

    def __init__(self, service, bus_path, properties):
        self.service = service
        self.bus_path = bus_path
        self.locked = False
        self.created = 0
        self.modified = 0
        self.label = properties["org.freedesktop.Secret.Collection.Label"]

        super().__init__(service.bus, bus_path)

    def get_items(self, path):
        items = self.service.db.find_items({"xdg:collection": self.bus_path})
        return dbus.Array(items, "o")

    def get_label(self, path):
        return dbus.String(self.label)

    def set_label(self, path, value):
        self.label = str(value)
        self.service.db.set_collection_properties(self.bus_path, {
            "org.freedesktop.Secret.Collection.Label": self.label,
        })

    def get_created(self, path):
        return dbus.UInt64(self.created)

    def get_modified(self, path):
        return dbus.UInt64(self.modified)

    INTERFACE = "org.freedesktop.Secret.Collection"
    PROPERTIES = {
        "Items":        (get_items,     None,       dbus.Array([], "o")),
        "Label":        (get_label,     set_label,  dbus.String("")),
        "Locked":       (None,          None,       dbus.Boolean(False)),
        "Created":      (get_created,   None,       dbus.UInt64(0)),
        "Modified":     (get_modified,  None,       dbus.UInt64(0)),
    }

    @dbus.service.method("org.freedesktop.Secret.Collection", "a{sv}(oayays)b", "oo",
                         sender_keyword="sender",
                         byte_arrays=True)
    def CreateItem(self, properties, secret, replace,
                   sender=None):
        label = properties["org.freedesktop.Secret.Item.Label"]
        attrs = properties["org.freedesktop.Secret.Item.Attributes"]

        attrs.setdefault("xdg:collection", self.bus_path)
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

        return (dbus.ObjectPath(bus_path), NullObject)

    @dbus.service.method("org.freedesktop.Secret.Collection", "", "o")
    def Delete(self):
        path = self.bus_path
        for (alias, target) in self.service.db.get_aliases():
            if path == target:
                self.remove_from_connection(self.bus, self.make_alias_path(alias))
        self.remove_from_connection(self.bus, path)
        del self.service.path_objects[path]
        del self.service.collections[path]
        self.service.db.delete_collection(path)
        self.service.CollectionDeleted(path)
        self.service.PropertiesChanged("org.freedesktop.Secret.Service",
                                       {"Collections": self.service.get_collections()},
                                       [])
        return NullObject

    @dbus.service.method("org.freedesktop.Secret.Collection", "a{ss}", "ao")
    def SearchItems(self, attributes):
        attributes["xdg:collection"] = self.bus_path
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
