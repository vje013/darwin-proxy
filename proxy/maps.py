"""Round-trip map lifecycle.

One-way mode persists nothing. Round-trip mode records original->replacement and
can serialize it encrypted (Fernet / AES-128-CBC + HMAC) with a TTL. The map is
the only thing that can reverse a pseudonym, so it is encrypted at rest, gated on
a separate secret, and self-expires: load() refuses an expired or wrong-key map.
"""
import base64
import hashlib
import json
import time

from cryptography.fernet import Fernet


class MapExpired(Exception):
    pass


def fernet_from_secret(secret):
    raw = secret.encode("utf-8") if isinstance(secret, str) else secret
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw).digest()))


class MapStore:
    def __init__(self):
        self._fwd = {}   # namespace -> {original: replacement}
        self._rev = {}   # namespace -> {replacement: original}

    def add(self, namespace, original, replacement):
        self._fwd.setdefault(namespace, {})[original] = replacement
        self._rev.setdefault(namespace, {})[replacement] = original

    def replacement_for(self, namespace, original):
        return self._fwd.get(namespace, {}).get(original)

    def reverse(self, namespace, replacement):
        return self._rev.get(namespace, {}).get(replacement)

    def to_blob(self, ttl_seconds=None):
        payload = {"fwd": self._fwd,
                   "expires_at": (time.time() + ttl_seconds) if ttl_seconds else None}
        return json.dumps(payload).encode("utf-8")

    def save(self, path, fernet, ttl_seconds=None):
        with open(path, "wb") as f:
            f.write(fernet.encrypt(self.to_blob(ttl_seconds)))

    @classmethod
    def load(cls, path, fernet):
        with open(path, "rb") as f:
            data = json.loads(fernet.decrypt(f.read()))  # InvalidToken on wrong key
        exp = data.get("expires_at")
        if exp is not None and time.time() > exp:
            raise MapExpired("map has expired")
        store = cls()
        for ns, mp in data["fwd"].items():
            for original, replacement in mp.items():
                store.add(ns, original, replacement)
        return store
