import dbus
import dbus.service

from .exception import InvalidArgsException

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