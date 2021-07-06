# secretsd

This is a generic backend for the libsecret API, used by various programs to store passwords and similar secrets. It mostly implements the [Secret Service API][api] specification, to act as an alternative to gnome-keyring-daemon and kwalletd.

![badge: "works on my machine"](https://img.shields.io/badge/works%20on%20my%20machine-yes-green.svg?style=flat)

  [api]: https://specifications.freedesktop.org/secret-service/latest/

## Dependencies

  * python-cryptography
  * python-dbus
  * python-gobject (3.x)
  * python-xdg

## Installation

secretsd is a user-level daemon which uses your D-Bus "session bus". It could be manually started through `systemd --user`:

    cp systemd/secretsd.service ~/.config/systemd/user/
    systemctl --user start secretsd

or automatically started on demand through D-Bus activation:

    cp systemd/secretsd.service ~/.config/systemd/user/
    cp dbus/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/

## Security

Secretsd does not aim to provide complete security like a modern password manager would; it only aims to allow using the libsecret API instead of ad-hoc loading of plaintext passwords from `~/.netrc` or similar files, but still relies on external protection for those files. In particular, item titles and attributes are **not** encrypted.

For now, all secrets are encrypted using a single "database key", which is stored in a regular file by default but can be provided through an environment variable, KWallet, or read from an external program. To specify the key source:

    secretsd -k file:${CREDENTIALS_DIRECTORY}/secrets.key
    secretsd -k env:DATABASE_KEY
    secretsd -k kwallet:
    secretsd -k exec:"pass Apps/secretsd"

(As secretsd is supposed to be a background service, it is strongly advised to _not_ use an external program which would show interactive prompts. And in particular avoid those which use GnuPG pinentry or otherwise make use of libsecret, for hopefuly obvious reasons.)

Individually encrypted collections are not yet supported, but planned in the future. (This will most likely be a fully separate layer of encryption, in addition to the database key.)
