import dbus

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
