# secretsd

Secretsd is a generic backend for the libsecret API, which is used by various programs to store passwords and similar secrets. It mostly implements the [Secret Service API][api] specification and can be used as an alternative to gnome-keyring-daemon and kwalletd on headless systems or minimal desktop environments.

![badge: "works on my machine: yes"](https://img.shields.io/badge/works%20on%20my%20machine-yes-success)
![badge: "tests pass: lol what tests"](https://img.shields.io/badge/tests%20pass-lol%20what%20tests-inactive)

  [api]: https://specifications.freedesktop.org/secret-service/latest/

## Dependencies

  * python-cryptography (or PyCryptodome)
  * python-dbus
  * python-gobject (3.x)
  * python-prctl (recommended)
  * python-xdg

Secretsd can use either PyCryptodome or python-cryptography. Set `CRYPTO_BACKEND=` to either `cryptography` or `cryptodome` depending on which one works better (i.e. doesn't try to spawn gcc a dozen times on startup, etc).

## Installation

secretsd is a user-level daemon (an agent) which connects to your D-Bus session bus. It can be manually started through `systemd --user`:

    systemctl --user link systemd/secretsd.service
    systemctl --user start secretsd

or automatically started "on demand" through D-Bus activation:

    cp systemd/secretsd.service ~/.config/systemd/user/
    cp dbus/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/

## Security

The primary goal of secretsd is to allow programs to use the libsecret "Secret Service" API on headless systems, instead of ad-hoc loading of plaintext passwords from various files (e.g. as a replacement to ~/.netrc). There is no attempt to reach the level of modern password managers, or to guard against other processes when the daemon is running.

  - Item names and attributes are **not** encrypted; they are stored in clear text within the SQLite database. (Attributes in the "Secret Service" API are used as the search key.) This is similar to "pass", which also encrypts only the actual password but not the metadata.

  - Item passwords (the "Secret" field of each item) are encrypted using AES-CFB (in hindsight, maybe not a very good choice). There's a MAC somewhere, technically.

  - All "Collections" in secretsd share the same data encryption key and are always unlocked on startup. The `Lock` and `Unlock` API functions are currently not supported. (In comparison, GNOME Keyring treats each collection as a separate database with its own encryption passphrase.)

  - Any program can use the "Secret Service" API to look up the secrets stored by any other program. (GNOME Keyring and "pass" work the same way; any unconfined app can read any stored secret.)

The database key is stored in a regular file next to the database by default, but can be read from an external program. (KWallet is also supported, although as of the time of writing, it probably has native Secret Service API support anyway.)

    secretsd -k file:$CREDENTIALS_DIRECTORY/secrets.key
    secretsd -k exec:"pass Apps/secretsd"
    secretsd -k exec:"tpm_unseal -z -i secrets.key.tpm"
    secretsd -k env:DATABASE_KEY
    secretsd -k kwallet:

The database key must be available on startup; delayed unlock using the `Unlock` API function is not implemented, but a similar result could be achieved by relying on D-Bus activation to start secretsd on-demand, after unlocking its key source in some other way.

As secretsd is supposed to be a background service, it is strongly advised to not use an external program which would show interactive prompts. In particular avoid prompters which themselves use libsecret, for hopefully obvious reasons (this by default includes GnuPG, as its pinentry tries to load passphrases from libsecret unless told otherwise).
