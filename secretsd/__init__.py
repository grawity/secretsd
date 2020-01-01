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

from .collection import SecretServiceCollection
from .database import SecretsDatabase
from .exception import *
from .item import SecretServiceItemFallback
from .session import SecretServiceSession
from .util import *

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
