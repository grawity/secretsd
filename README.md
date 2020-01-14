# secretsd

This is a generic backend for the libsecret API, used by various programs to store passwords and similar secrets. It is an alternative to gnome-keyring-daemon and kwalletd.

**Note:** This is a fork that does encrypt the password, and stores the encryption key in KWallet. Probably not helpful to anyone else but myself.

## Dependencies

  * python-cryptography
  * python-dbus
  * python-gobject (3.x)
  * python-xdg
  * python-pynacl

![badge](https://img.shields.io/badge/works%20on%20my%20machine-yes-green.svg?style=flat)
