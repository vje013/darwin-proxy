"""Keyed pseudonymization.

Consistency comes from a secret key, not a stored name table. The replacement
for a value is candidate_pool[ HMAC(key, field|value) mod len(pool) ]:
  - deterministic: same key + same value -> same replacement (consistency).
  - key-scoped: a different key yields a different mapping.
  - one-way: HMAC is preimage-resistant and the mod collapses many inputs to one
    pool entry, so the output cannot be reversed to the input from the key alone.

The candidate pools are generated once from a fixed public seed: that seed only
defines the universe of possible fake values. The secret key decides which value
a given input maps to. Public universe, secret selection.

One-way is the default: nothing reversible is written anywhere. Round-trip mode
records the mapping into a MapStore the pipeline can persist encrypted with a TTL.
"""
import hashlib
import hmac
import os

from faker import Faker

from proxy.classify import REGIONS, SECTOR_COMPANIES
from proxy.maps import MapStore

POOL_SEED = 1729
POOL_KEY_ENV = "PROXY_PSEUDONYM_KEY"

# Entities whose value is an identifier with a shape worth preserving (so joins on
# the token still work) but whose content must be destroyed. These get a
# format-preserving HMAC token rather than a pool draw.
FORMAT_ENTITIES = {
    "US_SSN", "CREDIT_CARD", "US_BANK_NUMBER", "FIN_ACCOUNT", "US_ABA_ROUTING",
    "US_EIN", "CUSIP", "ISIN", "IBAN_CODE", "PHONE_NUMBER", "US_ITIN",
    "US_PASSPORT", "US_DRIVER_LICENSE",
}


def _uniq(gen, n):
    seen, out = set(), []
    for _ in range(n):
        v = gen()
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _build_pools():
    f = Faker()
    f.seed_instance(POOL_SEED)
    return {
        "male": _uniq(f.first_name_male, 3000),
        "female": _uniq(f.first_name_female, 3000),
        "first": _uniq(f.first_name, 3000),
        "last": _uniq(f.last_name, 3000),
        "company": _uniq(f.company, 3000),
        "city": _uniq(f.city, 3000),
        "country": _uniq(f.country, 1000),
        "word": _uniq(f.word, 2000),
    }


POOLS = _build_pools()


def load_key(key=None):
    """Resolve the pseudonymization key. Explicit > env > ephemeral (run-scoped)."""
    if key is not None:
        return key if isinstance(key, bytes) else str(key).encode()
    env = os.environ.get(POOL_KEY_ENV)
    if env:
        try:
            return bytes.fromhex(env)
        except ValueError:
            return env.encode()
    return os.urandom(32)  # ephemeral: consistent within this run only, one-way


class Substitutor:
    def __init__(self, key=None, round_trip=False, seed=None):
        self.key = load_key(key)
        self.round_trip = round_trip
        self.store = MapStore() if round_trip else None
        self._cache = {}  # field -> {value: replacement} (in-memory only)

    def _idx(self, namespace, value, n):
        mac = hmac.new(self.key, f"{namespace}|{value}".encode("utf-8"), hashlib.sha256).digest()
        return int.from_bytes(mac, "big") % n

    def _pick(self, pool, namespace, value, exclude_value=True):
        candidates = [p for p in pool if p != value] if exclude_value else pool
        if not candidates:
            candidates = pool
        return candidates[self._idx(namespace, value, len(candidates))]

    def _remember(self, field, value, repl):
        self._cache.setdefault(field, {})[value] = repl
        if self.store is not None:
            self.store.add(field, value, repl)
        return repl

    def _cached(self, field, value):
        return self._cache.get(field, {}).get(value)

    # ---- v2: header-agnostic, entity-type dispatch -----------------------
    # Namespace is the entity type, so the same value yields the same token in
    # every column. That cross-column stability is the signal we preserve and is
    # what the commodity operators (replace/redact/mask/hash) destroy.
    def substitute_entity(self, entity_type, value):
        if value == "" or value is None:
            return value
        ns = entity_type or "GENERIC"
        hit = self._cached(ns, value)
        if hit is not None:
            return hit
        if entity_type in FORMAT_ENTITIES:
            return self._remember(ns, value, self._format_token(entity_type, ns, value))
        if entity_type == "PERSON":
            first = self._pick(POOLS["first"], ns + ":first", value)
            last = self._pick(POOLS["last"], ns + ":last", value)
            repl = f"{first} {last}"
        elif entity_type == "EMAIL_ADDRESS":
            first = self._pick(POOLS["first"], ns + ":first", value).lower()
            last = self._pick(POOLS["last"], ns + ":last", value).lower()
            repl = f"{first}.{last}@example.com"
        elif entity_type in ("ORG", "ORGANIZATION", "NRP"):
            repl = self._pick(POOLS["company"], ns, value)
        elif entity_type in ("LOCATION", "GPE"):
            repl = self._pick(POOLS["city"], ns, value)
        else:
            repl = self._pick(POOLS["word"], ns, value)
        return self._remember(ns, value, repl)

    def _format_token(self, entity_type, ns, value):
        mac = hmac.new(self.key, f"{ns}|{value}".encode("utf-8"), hashlib.sha256).hexdigest()
        d = "".join(str(int(c, 16) % 10) for c in mac)
        if entity_type == "US_SSN":
            return f"{d[:3]}-{d[3:5]}-{d[5:9]}"
        if entity_type == "US_EIN":
            return f"{d[:2]}-{d[2:9]}"
        if entity_type == "PHONE_NUMBER":
            return f"({d[:3]}) {d[3:6]}-{d[6:10]}"
        if entity_type == "CREDIT_CARD":
            return d[:16]
        if entity_type in ("US_ABA_ROUTING", "CUSIP"):
            return d[:9]
        # default: match the input's digit count so column width is preserved
        n = sum(c.isdigit() for c in value) or 10
        return d[:max(n, 4)]

    def substitute(self, field, entity_type, value, semantic_class):
        hit = self._cached(field, value)
        if hit is not None:
            return hit
        return self._remember(field, value, self._generate(field, entity_type, value, semantic_class))

    def _generate(self, field, entity_type, value, sc):
        if entity_type == "PERSON" and field == "First Name":
            g = sc.attributes.get("gender", "unknown")
            pool = POOLS["male"] if g in ("male", "mostly_male") else \
                POOLS["female"] if g in ("female", "mostly_female") else POOLS["first"]
            return self._pick(pool, field, value)
        if entity_type == "PERSON":
            return self._pick(POOLS["last"], field, value)
        if field == "State":
            region = sc.attributes.get("region")
            pool = REGIONS.get(region) or POOLS["word"]
            return self._pick(pool, field, value)
        if field == "City":
            return self._pick(POOLS["city"], field, value)
        if field == "Country":
            return self._pick(POOLS["country"], field, value)
        if entity_type == "ORG":
            sector = sc.attributes.get("sector")
            pool = SECTOR_COMPANIES.get(sector) or POOLS["company"]
            return self._pick(pool, field, value)
        return self._pick(POOLS["word"], field, value)

    def substitute_format(self, field, entity_type, value):
        hit = self._cached(field, value)
        if hit is not None:
            return hit
        mac = hmac.new(self.key, f"{field}|{value}".encode("utf-8"), hashlib.sha256).hexdigest()
        digits = "".join(str(int(c, 16) % 10) for c in mac)
        if entity_type == "PHONE":
            repl = f"({digits[:3]}) {digits[3:6]}-{digits[6:10]}"
        else:
            repl = f"{digits[:2]}-{digits[2:9]}"
        return self._remember(field, value, repl)

    def derive_email(self, field, value, context):
        hit = self._cached(field, value)
        if hit is not None:
            return hit
        first = context.get("First Name", "user")
        last = context.get("Last Name", "anon")
        return self._remember(field, value, f"{first.lower()}.{last.lower()}@example.com")
