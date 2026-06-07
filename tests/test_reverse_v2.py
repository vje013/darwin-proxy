"""Phase 4: reversibility dual-mode.
- map mode: keyed substitution stays realistic/joinable, reversible only via the
  encrypted, TTL-bound MapStore.
- encrypt mode: AES ciphertext, opaque, reversible by key alone, stateless.
Model-free: explicit mappings, no analyzer."""
import os
import tempfile

import pandas as pd
import pytest
from cryptography.fernet import InvalidToken

from proxy.ingest import Table
from proxy.maps import MapExpired
from proxy.substitute import Substitutor
from proxy.transform import Transformer

MAP = {"email": "EMAIL_ADDRESS", "ssn": "US_SSN"}


def _rows():
    return Table(pd.DataFrame({"email": ["a@x.com", "b@y.com", "a@x.com"],
                               "ssn": ["123-45-6789", "987-65-4320", "123-45-6789"]}))


# ---- map mode -------------------------------------------------------------

def test_map_mode_roundtrip():
    tr = Transformer(key="K", round_trip=True)
    anon, _ = tr.transform_table(_rows(), MAP)
    assert "a@x.com" not in set(anon.df["email"])           # anonymized
    back = tr.reverse_table(anon, MAP)
    assert list(back.df["email"]) == ["a@x.com", "b@y.com", "a@x.com"]
    assert list(back.df["ssn"])[0] == "123-45-6789"


def test_map_mode_is_signal_preserving():
    tr = Transformer(key="K", round_trip=True)
    anon, _ = tr.transform_table(_rows(), MAP)
    assert anon.df["email"][0].endswith("@example.com")     # realistic, not opaque
    assert anon.df["email"][0] == anon.df["email"][2]        # joinable


def test_map_persist_and_reverse_with_secret():
    tr = Transformer(key="K", round_trip=True)
    anon, _ = tr.transform_table(_rows(), MAP)
    p = os.path.join(tempfile.mkdtemp(), "m.enc")
    tr.save_map(p, "secret-A")
    other = Transformer(key="different", round_trip=True)   # map reverses, not the key
    other.load_map(p, "secret-A")
    assert list(other.reverse_table(anon, MAP).df["email"]) == ["a@x.com", "b@y.com", "a@x.com"]


def test_map_wrong_secret_rejected():
    tr = Transformer(key="K", round_trip=True)
    tr.transform_table(_rows(), MAP)
    p = os.path.join(tempfile.mkdtemp(), "m.enc")
    tr.save_map(p, "secret-A")
    with pytest.raises(InvalidToken):
        Transformer(round_trip=True).load_map(p, "secret-WRONG")


def test_map_ttl_expiry():
    tr = Transformer(key="K", round_trip=True)
    tr.transform_table(_rows(), MAP)
    p = os.path.join(tempfile.mkdtemp(), "m.enc")
    tr.save_map(p, "s", ttl_seconds=-1)                     # already expired
    with pytest.raises(MapExpired):
        Transformer(round_trip=True).load_map(p, "s")


def test_reverse_requires_round_trip():
    with pytest.raises(ValueError):
        Transformer(key="K").reverse_table(_rows(), MAP)    # round_trip not set


# ---- encrypt mode ---------------------------------------------------------

def test_encrypt_mode_roundtrip():
    tr = Transformer(key="K")
    enc, _ = tr.encrypt_table(_rows(), MAP)
    assert "@" not in enc.df["email"][0]                    # opaque ciphertext
    dec = tr.decrypt_table(enc, MAP)
    assert list(dec.df["email"]) == ["a@x.com", "b@y.com", "a@x.com"]
    assert list(dec.df["ssn"]) == ["123-45-6789", "987-65-4320", "123-45-6789"]


def test_encrypt_wrong_key_fails():
    tr = Transformer(key="K")
    enc, _ = tr.encrypt_table(_rows(), MAP)
    with pytest.raises(Exception):
        tr.decrypt_table(enc, MAP, key="0" * 32)            # wrong AES key


def test_modes_differ_opaque_vs_semantic():
    rows = _rows()
    semantic, _ = Transformer(key="K", round_trip=True).transform_table(rows, MAP)
    opaque, _ = Transformer(key="K").encrypt_table(rows, MAP)
    assert semantic.df["email"][0].endswith("@example.com")  # analyzable
    assert "@" not in opaque.df["email"][0]                  # not analyzable


# ---- substitution branch coverage (closes the substitute.py gap) ----------

def test_substitute_entity_branches():
    s = Substitutor(key="k")
    assert s.substitute_entity("US_SSN", "") == ""                 # blank passthrough
    assert len(s.substitute_entity("US_SSN", "1")) == 11           # XXX-XX-XXXX
    assert "-" in s.substitute_entity("US_EIN", "2")               # XX-XXXXXXX
    cc = s.substitute_entity("CREDIT_CARD", "3")
    assert len(cc) == 16 and cc.isdigit()
    assert len(s.substitute_entity("US_ABA_ROUTING", "4")) == 9
    assert s.substitute_entity("PHONE_NUMBER", "5").startswith("(")
    assert s.substitute_entity("IBAN_CODE", "GB1234567890").isdigit()  # default digit branch
    assert s.substitute_entity("PERSON", "Jane Doe").count(" ") == 1   # first last
    assert "@example.com" in s.substitute_entity("EMAIL_ADDRESS", "x@y.com")
    assert s.substitute_entity("ORG", "Acme Corp")                 # company pool
    assert s.substitute_entity("LOCATION", "Texas")                # city pool
    assert s.substitute_entity("UNKNOWN_TYPE", "foo")              # word default
