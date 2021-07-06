# secretsd

This is a generic backend for the libsecret API, used by various programs to store passwords and similar secrets. It is an alternative to gnome-keyring-daemon and kwalletd.

![badge](https://img.shields.io/badge/works%20on%20my%20machine-yes-green.svg?style=flat)

## Dependencies

  * python-cryptography
  * python-dbus
  * python-gobject (3.x)
  * python-xdg

## Storage

For now, all secrets are encrypted using a single "database key", which is stored in a regular file by default but can be provided through an environment variable, KWallet, or read from an external program. Item titles and attributes are **not** encrypted.

    secretsd -k file:${CREDENTIALS_DIRECTORY}/secrets.key
    secretsd -k env:DATABASE_KEY
    secretsd -k kwallet:
    secretsd -k exec:"pass Apps/secretsd"

(As secretsd is supposed to be a background service, it is strongly advised to _not_ use an external program which would show interactive prompts. And in particular avoid those which use GnuPG pinentry or otherwise make use of libsecret, for hopefuly obvious reasons.)

Individually encrypted collections are not yet supported, but planned in the future. (This will most likely be a fully separate layer of encryption, in addition to the database key.)
