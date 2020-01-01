#!/usr/bin/env python3
from collections import defaultdict
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import logging
import os
import time
import xdg.BaseDirectory

from .database import SecretsDatabase
from .session import SecretServiceSession

NullObject = dbus.ObjectPath("/")

def encode_path_component(value):
    return "".join([c if c.isalnum() else "_%02x" % ord(c) for c in value])

class Counter():
    def __init__(self, start):
        self.value = start

    def increment(self):
        v = self.value
        self.value += 1
        return v

class InvalidArgsException(dbus.DBusException):
    _dbus_error_name = "org.freedesktop.DBus.Error.InvalidArgs"

class NotYetImplementedException(dbus.DBusException):
    _dbus_error_name = "org.freedesktop.DBus.Error.NotSupported"
    def __init__(self):
        super().__init__("TODO: Not implemented")

class IsLockedException(dbus.DBusException):
    _dbus_error_name = "org.freedesktop.Secret.Error.IsLocked"

class NoSessionException(dbus.DBusException):
    _dbus_error_name = "org.freedesktop.Secret.Error.NoSession"

class NoSuchObjectException(dbus.DBusException):
    _dbus_error_name = "org.freedesktop.Secret.Error.NoSuchObject"

class BusObjectWithProperties():
    PROPERTIES = {}

    @dbus.service.method("org.freedesktop.DBus.Properties", "ss", "v",
                         path_keyword="path")
    def Get(self, interface, property, path=None):
        if interface == self.INTERFACE:
            if property in self.PROPERTIES:
                getter, setter, value = self.PROPERTIES[property]
                if getter:
                    value = getter(self, path)
                return value
            else:
                raise InvalidArgsException("No such property %r" % str(property))
        else:
            raise InvalidArgsException("No such interface %r" % str(interface))

    @dbus.service.method("org.freedesktop.DBus.Properties", "s", "a{sv}",
                         path_keyword="path")
    def GetAll(self, interface, path=None):
        if interface == self.INTERFACE:
            out = {}
            for name, (getter, setter, value) in self.PROPERTIES.items():
                if getter:
                    value = getter(self, path)
                out[name] = value
            return out
        else:
            raise InvalidArgsException("No such interface %r" % str(interface))

    @dbus.service.method("org.freedesktop.DBus.Properties", "ssv", "",
                         path_keyword="path")
    def Set(self, interface, property, value, path=None):
        if interface == self.INTERFACE:
            if property in self.PROPERTIES:
                getter, setter, _ = self.PROPERTIES[property]
                if setter:
                    setter(self, path, value)
                else:
                    raise InvalidArgsException("Property %r is read-only" % str(property))
            else:
                raise InvalidArgsException("No such property %r" % str(property))
        else:
            raise InvalidArgsException("No such interface %r" % str(interface))

class SecretServiceItemFallback(dbus.service.FallbackObject, BusObjectWithProperties):
    ROOT = "/org/freedesktop/secrets/item"
    PATH = "/org/freedesktop/secrets/item/i%d"

    def __init__(self, service, bus_path=ROOT):
        self.service = service
        self.bus_path = bus_path
        super().__init__(self.service.bus, self.bus_path)

    def get_attributes(self, path):
        attrs = self.service.db.get_attributes(path)
        if attrs is None:
            raise NoSuchObjectException(path)
        attrs.setdefault("xdg:schema", "org.freedesktop.Secret.Generic")
        return attrs

    def set_attributes(self, path, value):
        if not self.service.db.item_exists(path):
            raise NoSuchObjectException(path)
        self.service.db.set_attributes(path, value)

    def get_label(self, path):
        meta = self.service.db.get_metadata(path)
        if not meta:
            raise NoSuchObjectException(path)
        return meta[0]

    def set_label(self, path, value):
        if not self.service.db.item_exists(path):
            raise NoSuchObjectException(path)
        self.service.db.set_metadata_label(path, value)

    def get_created(self, path):
        meta = self.service.db.get_metadata(path)
        if not meta:
            raise NoSuchObjectException(path)
        return dbus.UInt64(meta[1])

    def get_modified(self, path):
        meta = self.service.db.get_metadata(path)
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
        self.service.db.delete_item(path)
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

class SecretService(dbus.service.Object, BusObjectWithProperties):
    def __init__(self, bus, sdb):
        self.bus = bus
        self.db = sdb
        self.bus_name = dbus.service.BusName("org.freedesktop.secrets", self.bus)
        self.path_objects = {}
        self.next_object = 0
        self.client_objects = defaultdict(list)
        self.collections = {}

        super().__init__(self.bus, "/org/freedesktop/secrets")

        self.fallback_item = SecretServiceItemFallback(self)
        self.compat_fallback_item = SecretServiceItemFallback(self,
                                    "/lt/nullroute/secretsd/item")

        self.load_collections()
        self.create_collection("login", {
            "org.freedesktop.Secret.Collection.Label": "Login keyring",
        })
        self.create_collection("default", {
            "org.freedesktop.Secret.Collection.Label": "Default keyring",
        })

    def get_collections(self, path):
        collections = self.db.list_collections()
        return dbus.Array(collections, "o")

    def load_collections(self):
        for path in self.db.list_collections():
            props = self.db.get_collection_properties(path)
            crtime, mtime = self.db.get_collection_metadata(path)
            col = SecretServiceCollection(self, path, props)
            col.created = crtime
            col.modified = mtime
            self.path_objects[path] = col
            self.collections[path] = col

        for (alias, target) in self.db.get_aliases():
            col = self.collections[target]
            col.add_to_connection(self.bus, self.make_alias_path(alias))

    def create_collection(self, alias, properties):
        if alias != "":
            path = self.db.resolve_alias(alias)
            if path:
                print("create_collection(%r) found alias path %r" % (alias, path))
                return dbus.ObjectPath(path)

        col = self.make_object(None, True, SecretServiceCollection, properties)
        col.created = int(time.time())
        col.modified = int(time.time())
        print("create_collection(%r) made path %r" % (alias, col))
        self.db.add_collection(col.bus_path, properties)
        self.path_objects[col.bus_path] = col
        self.collections[col.bus_path] = col
        if alias != "":
            self.db.add_alias(alias, col.bus_path)
            col.add_to_connection(self.bus, self.make_alias_path(alias))
        return col.bus_path

    INTERFACE = "org.freedesktop.Secret.Service"
    PROPERTIES = {
        "Collections": (get_collections, None, None),
    }

    def make_alias_path(self, alias):
        return "/org/freedesktop/secrets/aliases/%s" % encode_path_component(alias)

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
        print("CreateCollection(%r, %r)" % (properties, alias))
        path = self.create_collection(alias, properties)
        self.CollectionCreated(path)
        self.PropertiesChanged("org.freedesktop.Secret.Service",
                               {"Collections": self.get_collections()},
                               [])
        return (dbus.ObjectPath(path), NullObject)

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
        if collection not in self.collections:
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

os.umask(0o077)

db_dir = xdg.BaseDirectory.save_data_path("nullroute.eu.org/secretsd")
db_path = os.path.join(db_dir, "secrets.db")

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
sdb = SecretsDatabase(db_path)
svc = SecretService(bus, sdb)

loop = GLib.MainLoop()
loop.run()
