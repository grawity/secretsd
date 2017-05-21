# secretsd

This is a generic backend for the libsecret API, used by various programs to store passwords and similar secrets. It is an alternative to gnome-keyring-daemon and kwalletd.

**Note:** Currently secretsd does not encrypt the stored passwords in any way. Patches requested.

## Dependencies

  * python-cryptography
  * python-dbus
  * python-gobject (3.x)
  * python-xdg

![badge](https://img.shields.io/badge/works%20on%20my%20machine-yes-green.svg?style=flat)
