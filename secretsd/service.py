from collections import defaultdict
import dbus
import dbus.service
import time

from .collection import SecretServiceCollectionFallback
from .exception import *
from .item import SecretServiceItemFallback
from .session import SecretServiceSession
from .util import BusObjectWithProperties, NullObject

def encode_path_component(value):
    return "".join([c if c.isalnum() else "_%02x" % ord(c) for c in value])

class SecretService(dbus.service.Object, BusObjectWithProperties):
    def __init__(self, bus, sdb):
        self.bus = bus
        self.db = sdb
        self.bus_name = dbus.service.BusName("org.freedesktop.secrets", self.bus)
        self.path_objects = {}
        self.next_object = 0
        self.client_objects = defaultdict(list)

        super().__init__(self.bus, "/org/freedesktop/secrets")

        self.fallback_item = SecretServiceItemFallback(self)
        self.fallback_collection = SecretServiceCollectionFallback(self)
        self.fallback_alias = SecretServiceCollectionFallback(self, "/org/freedesktop/secrets/aliases")

    def get_collections(self, path=None):
        collections = self.db.list_collections()
        return dbus.Array(collections, "o")

    INTERFACE = "org.freedesktop.Secret.Service"
    PROPERTIES = {
        "Collections": (get_collections, None, None),
    }

    def make_bus_path(self, persist, type):
        if persist:
            bus_path = type.PATH % self.db.get_next_object_id()
        else:
            bus_path = type.PATH % self.next_object
            self.next_object += 1
        return bus_path

    def make_object(self, sender, persist, type, *args, **kwargs):
        bus_path = self.make_bus_path(persist, type)
        object = type(self, bus_path, *args, **kwargs)
        self.path_objects[bus_path] = object
        if sender:
            self.client_objects[sender].append(bus_path)
        return object

    def gc_client(self, sender):
        # TODO: hook this up
        if sender in self.client_objects:
            for path in self.client_objects[sender]:
                del self.path_objects[path]
            del self.client_objects[sender]

    ## bus methods

    @dbus.service.method("org.freedesktop.Secret.Service", "a{sv}s", "oo",
                         sender_keyword="sender")
    def CreateCollection(self, properties, alias,
                         sender=None):
        label = properties["org.freedesktop.Secret.Collection.Label"]
        bus_path = self.make_bus_path(True, SecretServiceCollectionFallback)
        self.db.add_collection(bus_path, label)
        if alias:
            self.db.add_alias(alias, bus_path)
        self.CollectionCreated(bus_path)
        self.PropertiesChanged("org.freedesktop.Secret.Service",
                               {"Collections": self.get_collections()},
                               [])

        return (dbus.ObjectPath(bus_path), NullObject)

    @dbus.service.method("org.freedesktop.Secret.Service", "aoo", "a{o(oayays)}")
    def GetSecrets(self, items, session):
        session = self.path_objects[session]
        out = {}
        for item_path in items:
            sec_data, sec_type = self.db.get_secret(item_path)
            sec_ct, sec_iv = session.encrypt(sec_data)
            out[item_path] = (session.bus_path, sec_iv, sec_ct, sec_type)
        return out

    @dbus.service.method("org.freedesktop.Secret.Service", "sv", "vo",
                         sender_keyword="sender",
                         byte_arrays=True)
    def OpenSession(self, algorithm, input, sender=None):
        session = self.make_object(sender, False, SecretServiceSession, algorithm)
        output, done = session.kex(input)
        if done:
            return (output, session.bus_path)
        else:
            return (output, NullObject)

    @dbus.service.method("org.freedesktop.Secret.Service", "s", "o")
    def ReadAlias(self, alias):
        path = self.db.resolve_alias(alias)
        if path is None:
            return NullObject
        else:
            return dbus.ObjectPath(path)

    @dbus.service.method("org.freedesktop.Secret.Service", "so", "")
    def SetAlias(self, alias, collection):
        if alias != "default":
            raise dbus.DBusException("Only the 'default' alias is supported",
                                     name="org.freedesktop.DBus.Error.NotSupported")
        if not self.db.collection_exists(collection):
            raise dbus.DBusException("Collection with path %r not found" % (str(collection),),
                                     name="org.freedesktop.DBus.Error.InvalidArgs")
        self.db.add_alias(alias, collection)

    @dbus.service.method("org.freedesktop.Secret.Service", "a{ss}", "aoao")
    def SearchItems(self, attributes):
        items = self.db.find_items(attributes)
        return (items, [])

    @dbus.service.method("org.freedesktop.Secret.Service", "ao", "aoo")
    def Lock(self, objects):
        print("TODO: Service.Lock(%r)" % objects)
        raise NotYetImplementedException()

    @dbus.service.method("org.freedesktop.Secret.Service", "ao", "aoo")
    def Unlock(self, objects):
        return (objects, NullObject)

    @dbus.service.signal("org.freedesktop.DBus.Properties", "sa{sv}as")
    def PropertiesChanged(self, interface, changed_props, invalidated_props):
        pass

    @dbus.service.signal("org.freedesktop.Secret.Service", "o")
    def CollectionCreated(self, bus_path):
        pass

    @dbus.service.signal("org.freedesktop.Secret.Service", "o")
    def CollectionDeleted(self, bus_path):
        pass

    @dbus.service.signal("org.freedesktop.Secret.Service", "o")
    def CollectionChanged(self, bus_path):
        pass
