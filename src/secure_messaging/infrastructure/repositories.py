from contextlib import closing
from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from secure_messaging.entities.keys import KeyPair
from secure_messaging.infrastructure.exceptions import CryptoException


class IKeyRepository(Protocol):
    def save(self, owner: str, pair: KeyPair) -> None: ...
    def load(self, owner: str) -> KeyPair: ...
    def revoke(self, owner: str) -> None: ...
    def is_revoked(self, owner: str) -> bool: ...


class FileKeyRepository:
    """SQLite file with immutable owner bindings and encrypted PKCS#8 material."""
    def __init__(self, directory, password_provider):
        if not callable(password_provider):
            raise CryptoException("A password provider is required")
        directory = Path(directory)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CryptoException("Cannot create key directory") from exc
        self._path = directory / "keys.sqlite3"
        self._password = password_provider
        self._execute("""CREATE TABLE IF NOT EXISTS keys
            (owner TEXT PRIMARY KEY, pem BLOB NOT NULL, created TEXT NOT NULL,
             expires TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)""")

    def _execute(self, sql, args=()):
        try:
            with closing(sqlite3.connect(self._path)) as conn, conn:
                cursor = conn.execute(sql, args)
                return cursor.fetchone(), cursor.rowcount
        except sqlite3.IntegrityError as exc:
            raise CryptoException("Owner already has a key") from exc
        except sqlite3.Error as exc:
            raise CryptoException("Key repository unavailable") from exc

    def save(self, owner, pair):
        if not isinstance(owner, str) or not owner.strip():
            raise CryptoException("Owner required")
        self._execute("INSERT INTO keys(owner,pem,created,expires) VALUES (?,?,?,?)",
                      (owner, pair.private.export_encrypted(self._password()),
                       pair.public.created_at.isoformat(), pair.public.expires_at.isoformat()))

    def load(self, owner):
        row, _ = self._execute("SELECT pem,created,expires FROM keys WHERE owner=?", (owner,))
        if row is None:
            raise CryptoException("Unknown owner")
        try:
            key = serialization.load_pem_private_key(row[0], self._password())
            return KeyPair.from_private(key, datetime.fromisoformat(row[1]), datetime.fromisoformat(row[2]))
        except (ValueError, TypeError) as exc:
            raise CryptoException("Cannot unlock stored key") from exc

    def revoke(self, owner):
        _, count = self._execute("UPDATE keys SET revoked=1 WHERE owner=?", (owner,))
        if not count:
            raise CryptoException("Unknown owner")

    def is_revoked(self, owner):
        row, _ = self._execute("SELECT revoked FROM keys WHERE owner=?", (owner,))
        if row is None:
            raise CryptoException("Unknown owner")
        return bool(row[0])


class InMemoryKeyRepository:
    def __init__(self):
        self._keys = {}
        self._revoked = set()

    def save(self, owner, pair):
        if not isinstance(owner, str) or not owner.strip() or owner in self._keys:
            raise CryptoException("Invalid or duplicate owner")
        self._keys[owner] = pair

    def load(self, owner):
        try:
            return self._keys[owner]
        except KeyError as exc:
            raise CryptoException("Unknown owner") from exc

    def revoke(self, owner):
        self.load(owner)
        self._revoked.add(owner)

    def is_revoked(self, owner):
        self.load(owner)
        return owner in self._revoked
