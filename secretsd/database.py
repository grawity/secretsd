import sqlite3
import time

class SecretsDatabase():
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.initialize()
        self.upgrade()

    def initialize(self):
        cur = self.db.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS version (" \
                    "   version INTEGER" \
                    ")")
        cur.execute("CREATE TABLE IF NOT EXISTS sequence (" \
                    "   next INTEGER" \
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

    def upgrade(self):
        print("DB: current database version is %d" % self.get_version())
        if self.get_version() == 0:
            print("DB: upgrading to version %d" % (1,))
            self._upgrade_v0_to_v1()
            self.db.cursor().execute("UPDATE version SET version = ?", (1,))
            self.db.commit()
        print("DB: new database version is %d" % self.get_version())

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
        cur.execute("INSERT INTO secrets VALUES (?,?,?)", (object, secret, sec_type))
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
        return cur.fetchone()

    def set_secret(self, object, secret, sec_type):
        print("DB: updating secret for %r" % object)
        if hasattr(secret, "encode"):
            raise ValueError("secret needs to be bytes, not str")
        now = int(time.time())
        cur = self.db.cursor()
        cur.execute("UPDATE secrets SET secret = ?, type = ? WHERE object = ?",
                    (secret, sec_type, object))
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
