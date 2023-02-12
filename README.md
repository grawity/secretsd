# secretsd

This is a generic backend for the libsecret API, used by various programs to store passwords and similar secrets. It mostly implements the [Secret Service API][api] specification, to act as an alternative to gnome-keyring-daemon and kwalletd.

![badge: "works on my machine: yes"](https://img.shields.io/badge/works%20on%20my%20machine-yes-success)
![badge: "tests pass: lol what tests"](https://img.shields.io/badge/tests%20pass-lol%20what%20tests-inactive)

  [api]: https://specifications.freedesktop.org/secret-service/latest/

## Dependencies

  * python-cryptography (or pycryptodome)
  * python-dbus
  * python-gobject (3.x)
  * python-xdg

## Installation

secretsd is a user-level daemon (an agent) which connects to your D-Bus session bus. It can be manually started through `systemd --user`:

    systemctl --user link systemd/secretsd.service
    systemctl --user start secretsd

or automatically started "on demand" through D-Bus activation:

    cp systemd/secretsd.service ~/.config/systemd/user/
    cp dbus/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/

## Security

Secretsd does not aim to provide complete security like a modern password manager would; it **only** aims to allow using the libsecret API on headless systems instead of ad-hoc loading of plaintext passwords from various files (e.g. to replace ~/.netrc), but still relies on external protection for those files. In particular, item titles and attributes are **not** encrypted (only the secret itself is), and overall it is only good enough to make the user feel a little bit better.

For now, all secrets are encrypted using a single "database key", which is stored in a regular file by default but can be provided through an environment variable, KWallet, or read from an external program. To specify the key source:

    secretsd -k file:$CREDENTIALS_DIRECTORY/secrets.key
    secretsd -k env:DATABASE_KEY
    secretsd -k kwallet:
    secretsd -k exec:"pass Apps/secretsd"
    secretsd -k exec:"tpm_unseal -z -i \$SECRETSD_DIR/secrets.key.tpm"

(As secretsd is supposed to be a background service, it is strongly advised to _not_ use an external program which would show interactive prompts. In particular avoid helpers which use libsecret, for hopefully obvious reasons – this includes GnuPG, as its Pinentry tries to load passphrases from libsecret!)

Individually encrypted collections are not yet supported, but planned in the future. (This will most likely be a fully separate layer of encryption, using a password-derived key in addition to the database key.)
