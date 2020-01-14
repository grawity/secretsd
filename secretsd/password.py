import binascii
import dbus
import nacl.secret
import nacl.utils


app_id = 'secretsd'
password_name = f"{app_id} encryption key"


def get_encryption_key():
    # Connect to KWallet to store the encryption key
    bus = dbus.SessionBus()
    kwallet = bus.get_object('org.kde.kwalletd5', '/modules/kwalletd5')
    interface = dbus.Interface(kwallet, 'org.kde.KWallet')
    local_wallet = interface.localWallet()
    handle_id = interface.open(local_wallet, 0, app_id)

    key_exists = interface.keyDoesNotExist(local_wallet, "Passwords", password_name)

    if key_exists == 1:
        # Encryption key doesn't exist already, generate a new one via NaCl
        encryption_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        encryption_key_hex = binascii.hexlify(encryption_key)
        interface.writePassword(handle_id, "Passwords", password_name, encryption_key_hex, app_id)
    elif key_exists == 0:
        # Encryption key exists already, retreieve it & transform back from hex
        encryption_key_hex = interface.readPassword(handle_id, "Passwords", password_name, app_id)
        encryption_key = binascii.unhexlify(encryption_key_hex)
    else:
        # Weird impossible state
        encryption_key = None

    interface.disconnectApplication(local_wallet, app_id)

    return encryption_key
