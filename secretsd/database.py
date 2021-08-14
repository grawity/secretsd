import base64
import sqlite3
import time

from .encryption import (generate_key,
                         aes_cfb8_wrap, aes_cfb8_unwrap,
                         aes_cfb128_wrap, aes_cfb128_unwrap)
from .external_keys import load_ext_key, store_ext_key

class SecretsDatabase():
    def __init__(self, path, key_path):
        self.db = sqlite3.connect(path)
        self.kp = key_path
        self.mk = None
        self.dk = None
        self.ver = 0
        self.initialize()
        self.upgrade()
        self.load_keys()

    def initialize(self):
        cur = self.db.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS version (" \
                    "   version INTEGER" \
                    ")")
        cur.execute("CREATE TABLE IF NOT EXISTS sequence (" \
                    "   next INTEGER" \
                    ")")
        cur.execute("CREATE TABLE IF NOT EXISTS parameters (" \
                    "   name TEXT," \
                    "   value TEXT" \
                    ")")
        cur.execute("CREATE TABLE IF NOT EXISTS collections (" \
                    "   object TEXT," \
                    "   label TEXT," \
                    "   created INTEGER," \
                    "   modified INTEGER" \
                    ")")
        cur.execute("CREATE TABLE IF NOT EXISTS aliases (" \
                    "   alias TEXT," \
                    "   target TEXT" \
                    ")")
        cur.execute("CREATE TABLE IF NOT EXISTS items (" \
                    "   object TEXT," \
                    "   label TEXT," \
                    "   created INTEGER," \
                    "   modified INTEGER" \
                    ")")
        cur.execute("CREATE TABLE IF NOT EXISTS attributes (" \
                    "   object TEXT," \
                    "   attribute TEXT," \
                    "   value TEXT" \
                    ")")
        cur.execute("CREATE TABLE IF NOT EXISTS secrets (" \
                    "   object TEXT," \
                    "   secret TEXT," \
                    "   type TEXT" \
                    ")")
        self.db.commit()

    # Encryption keys

    def _store_mkey(self, key):
        print("DB: storing master key to %r" % (self.kp))
        store_ext_key(self.kp, base64.b64encode(key).decode())

    def _load_mkey(self):
        print("DB: loading master key from %r" % (self.kp))
        try:
            mkey = base64.b64decode(load_ext_key(self.kp))
            if len(mkey) != 32:
                raise IOError("wrong mkey length (expected 32 bytes)")
        except (KeyError, FileNotFoundError):
            raise RuntimeError("could not load the database key from %r" % (self.kp))
        self.mk = mkey

    def _load_dkey(self, *, v=0):
        if (v or self.ver) == 3:
            cur = self.db.cursor()
            cur.execute("SELECT value FROM parameters WHERE name = 'dkey'")
            dkey, = cur.fetchone()
            try:
                dkey = self._decrypt_buf(dkey, with_mkey=True, v=3)
            except IOError as e:
                raise IOError("wrong mkey (%s)" % e)
            if len(dkey) != 32:
                raise IOError("wrong dkey length (expected 32 bytes)")
            self.dk = dkey
        else:
            raise NotImplementedError()

    def load_keys(self):
        if self.ver >= 2:
            self._load_mkey()
            self._load_dkey()

    def _encrypt_buf(self, buf, *, with_mkey=False, v=0):
        key = self.mk if with_mkey else self.dk
        if (v or self.ver) >= 3:
            return aes_cfb128_wrap(buf, key)
        elif (v or self.ver) == 2:
            return aes_cfb8_wrap(buf, key)
        else:
            raise NotImplementedError()

    def _decrypt_buf(self, buf, *, with_mkey=None, v=0):
        key = self.mk if with_mkey else self.dk
        if (v or self.ver) >= 3:
            return aes_cfb128_unwrap(buf, key)
        elif (v or self.ver) == 2:
            return aes_cfb8_unwrap(buf, key)
        else:
            raise NotImplementedError()

    # Schema upgrades

    def _upgrade_v0_to_v1(self):
        # Undo commit affc514 "make items use bus paths underneath their collection"
        cur = self.db.cursor()
        cur.execute("SELECT object FROM items" \
                    " WHERE object LIKE '/org/freedesktop/secrets/collection/c%/i%'")
        res = cur.fetchall()
        for (old_object,) in res:
            item_id = old_object.split("/")[-1]
            new_object = "/org/freedesktop/secrets/item/%s" % item_id
            print("DB: moving object %r => %r" % (old_object, new_object))
            cur.execute("UPDATE items      SET object = ? WHERE object = ?",
                        (new_object, old_object))
            cur.execute("UPDATE secrets    SET object = ? WHERE object = ?",
                        (new_object, old_object))
            cur.execute("UPDATE attributes SET object = ? WHERE object = ?",
                        (new_object, old_object))

    def _upgrade_v1_to_v2(self):
        # Version 2 encrypts all secrets using the database master key
        cur = self.db.cursor()
        # Generate a "master key"
        print("DB: generating a master key")
        mkey = generate_key()
        self._store_mkey(mkey)
        self.mk = mkey
        # Generate a "data key"
        print("DB: generating a data key")
        dkey = generate_key()
        blob = self._encrypt_buf(dkey, with_mkey=True, v=2)
        cur.execute("INSERT INTO parameters VALUES ('dkey', ?)", (blob,))
        self.dk = dkey
        # Encrypt all currently stored secrets
        cur.execute("SELECT object, secret FROM secrets")
        res = cur.fetchall()
        for object, blob in res:
            print("DB: encrypting secret %r" % (object,))
            blob = self._encrypt_buf(blob, v=2)
            cur.execute("UPDATE secrets SET secret = ? WHERE object = ?", (blob, object))

    def _upgrade_v2_to_v3(self):
        # Version 3 uses AES-CFB128 instead of (badly chosen) AES-CFB8
        cur = self.db.cursor()
        # Re-encrypt the data key
        self._load_mkey()
        cur.execute("SELECT value FROM parameters WHERE name = 'dkey'")
        blob, = cur.fetchone()
        blob = self._decrypt_buf(blob, with_mkey=True, v=2)
        blob = self._encrypt_buf(blob, with_mkey=True, v=3)
        cur.execute("UPDATE parameters SET value = ? WHERE name = 'dkey'", (blob,))
        # Re-encrypt all currently stored secrets
        self._load_dkey(v=3)
        cur.execute("SELECT object, secret FROM secrets")
        res = cur.fetchall()
        for object, blob in res:
            print("DB: re-encrypting secret %r" % (object,))
            blob = self._decrypt_buf(blob, v=2)
            blob = self._encrypt_buf(blob, v=3)
            cur.execute("UPDATE secrets SET secret = ? WHERE object = ?", (blob, object))

    def upgrade(self):
        print("DB: current database version is %d" % self.get_version())
        if self.get_version() == 0:
            print("DB: upgrading to version %d" % (1,))
            self._upgrade_v0_to_v1()
            self.db.cursor().execute("UPDATE version SET version = ?", (1,))
            self.db.commit()
        if self.get_version() == 1:
            print("DB: upgrading to version %d" % (2,))
            self._upgrade_v1_to_v2()
            self.db.cursor().execute("UPDATE version SET version = ?", (2,))
            self.db.commit()
            print("DB: vacuuming database")
            self.db.cursor().execute("VACUUM")
        if self.get_version() == 2:
            print("DB: upgrading to version %d" % (3,))
            self._upgrade_v2_to_v3()
            self.db.cursor().execute("UPDATE version SET version = ?", (3,))
            self.db.commit()
        self.ver = self.get_version()
        print("DB: new database version is %d" % self.ver)

    def get_version(self):
        cur = self.db.cursor()
        cur.execute("SELECT version FROM version")
        res = cur.fetchone()
        if res:
            version = res[0]
        else:
            version = 0
            cur.execute("INSERT INTO version VALUES (?)", (version,))
            self.db.commit()
        return version

    def get_next_object_id(self):
        cur = self.db.cursor()
        cur.execute("SELECT next FROM sequence")
        res = cur.fetchone()
        if res:
            oid = res[0]
            cur.execute("UPDATE sequence SET next = next + 1")
        else:
            oid = 0
            cur.execute("INSERT INTO sequence VALUES (?)", (oid + 1,))
        self.db.commit()
        print("DB: allocated new object ID %r" % oid)
        return oid

    # Collections

    def add_collection(self, object, label):
        print("DB: adding collection %r with label %r" % (object, label))
        now = int(time.time())
        cur = self.db.cursor()
        cur.execute("INSERT INTO collections VALUES (?,?,?,?)", (object, label, now, now))
        self.db.commit()

    def list_collections(self):
        cur = self.db.cursor()
        cur.execute("SELECT object FROM collections")
        return [r[0] for r in cur.fetchall()]

    def collection_exists(self, object):
        return bool(self.get_collection_metadata(object))

    def get_collection_metadata(self, object):
        print("DB: getting collection metadata for %r" % (object,))
        cur = self.db.cursor()
        cur.execute("SELECT label, created, modified FROM collections WHERE object = ?",
                    (object,))
        return cur.fetchone()

    def set_collection_label(self, object, label):
        print("DB: setting label for %r to %r" % (object, label))
        now = int(time.time())
        cur = self.db.cursor()
        cur.execute("UPDATE collections SET label = ?, modified = ? WHERE object = ?",
                    (label, now, object))
        self.db.commit()

    def delete_collection(self, object):
        print("DB: deleting collection %r" % (object,))
        cur = self.db.cursor()
        subquery = "SELECT object FROM attributes" \
                   " WHERE attribute = 'xdg:collection' AND value = ?"
        cur.execute("DELETE FROM items WHERE object IN (" + subquery + ")", (object,))
        cur.execute("DELETE FROM secrets WHERE object IN (" + subquery + ")", (object,))
        cur.execute("DELETE FROM attributes WHERE object IN (" + subquery + ")", (object,))
        cur.execute("DELETE FROM aliases WHERE target = ?", (object,))
        cur.execute("DELETE FROM collections WHERE object = ?", (object,))
        self.db.commit()

    # Aliases

    def add_alias(self, alias, target):
        print("DB: adding alias %r -> %r" % (alias, target))
        cur = self.db.cursor()
        cur.execute("DELETE FROM aliases WHERE alias = ?", (alias,))
        cur.execute("INSERT INTO aliases VALUES (?,?)", (alias, target))
        self.db.commit()

    def get_aliases(self):
        cur = self.db.cursor()
        cur.execute("SELECT alias, target FROM aliases")
        return cur.fetchall()

    def resolve_alias(self, alias):
        print("DB: resolving alias %r" % (alias,))
        cur = self.db.cursor()
        cur.execute("SELECT target FROM aliases WHERE alias = ?", (alias,))
        r = cur.fetchone()
        return r[0] if r else None

    def delete_alias(self, alias):
        print("DB: deleting alias %r" % (alias,))
        cur = self.db.cursor()
        cur.execute("DELETE FROM aliases WHERE alias = ?", (alias,))
        self.db.commit()

    # Items

    def add_item(self, object, label, attrs, secret, sec_type):
        now = int(time.time())
        cur = self.db.cursor()
        cur.execute("INSERT INTO items VALUES (?,?,?,?)", (object, label, now, now))
        for key, val in attrs.items():
            cur.execute("INSERT INTO attributes VALUES (?,?,?)", (object, key, val))
        cur.execute("INSERT INTO secrets VALUES (?,?,?)", (object, self._encrypt_buf(secret),
                                                           sec_type))
        self.db.commit()

    def find_items(self, match_attrs):
        qry = "SELECT object FROM attributes WHERE attribute = ? AND value = ?"
        qry = " INTERSECT ".join([qry] * len(match_attrs))
        parvs = []
        for k, v in match_attrs.items():
            parvs += [k, v]
        print("DB: searching for %r" % parvs)
        cur = self.db.cursor()
        cur.execute(qry, parvs)
        return [r[0] for r in cur.fetchall()]

    def item_exists(self, object):
        return bool(self.get_item_metadata(object))

    def get_item_metadata(self, object):
        print("DB: getting metadata for %r" % object)
        cur = self.db.cursor()
        cur.execute("SELECT label, created, modified FROM items WHERE object = ?",
                    (object,))
        return cur.fetchone()

    def set_item_label(self, object, label):
        print("DB: setting label for %r to %r" % (object, label))
        now = int(time.time())
        cur = self.db.cursor()
        cur.execute("UPDATE items SET label = ?, modified = ? WHERE object = ?",
                    (label, now, object))
        self.db.commit()

    def get_item_attributes(self, object):
        print("DB: getting attrs for %r" % object)
        cur = self.db.cursor()
        cur.execute("SELECT attribute, value FROM attributes WHERE object = ?", (object,))
        return {k: v for k, v in cur.fetchall()}

    def set_item_attributes(self, object, attrs):
        print("DB: setting attrs for %r to %r" % (object, attrs))
        now = int(time.time())
        cur = self.db.cursor()
        cur.execute("DELETE FROM attributes WHERE object = ?", (object,))
        for key, val in attrs.items():
            cur.execute("INSERT INTO attributes VALUES (?,?,?)", (object, key, val))
        cur.execute("UPDATE items SET modified = ? WHERE object = ?", (now, object))
        self.db.commit()

    def get_secret(self, object):
        print("DB: getting secret for %r" % object)
        cur = self.db.cursor()
        cur.execute("SELECT secret, type FROM secrets WHERE object = ?", (object,))
        secret, sec_type = cur.fetchone()
        return self._decrypt_buf(secret), sec_type

    def set_secret(self, object, secret, sec_type):
        print("DB: updating secret for %r" % object)
        if hasattr(secret, "encode"):
            raise ValueError("secret needs to be bytes, not str")
        now = int(time.time())
        cur = self.db.cursor()
        cur.execute("UPDATE secrets SET secret = ?, type = ? WHERE object = ?",
                    (self._encrypt_buf(secret), sec_type, object))
        cur.execute("UPDATE items SET modified = ? WHERE object = ?",
                    (now, object))
        self.db.commit()

    def delete_item(self, object):
        print("DB: deleting item %r" % object)
        cur = self.db.cursor()
        cur.execute("DELETE FROM attributes WHERE object = ?", (object,))
        cur.execute("DELETE FROM secrets WHERE object = ?", (object,))
        cur.execute("DELETE FROM items WHERE object = ?", (object,))
        self.db.commit()
