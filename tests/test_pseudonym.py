"""Phase 4: keyed pseudonymization + map lifecycle."""
import time

import pytest
from cryptography.fernet import InvalidToken

from proxy.substitute import Substitutor
from proxy.schemas import SemanticClass
from proxy.classify import REGIONS
from proxy.maps import MapStore, fernet_from_secret, MapExpired


def _sc(field, etype, **attrs):
    return SemanticClass(field=field, entity_type=etype, attributes=attrs)


def test_same_key_same_value_consistent():
    a = Substitutor(key="k1")
    b = Substitutor(key="k1")
    sc = _sc("First Name", "PERSON", gender="male")
    assert a.substitute("First Name", "PERSON", "John", sc) == \
           b.substitute("First Name", "PERSON", "John", sc)


def test_different_key_different_mapping():
    sc = _sc("First Name", "PERSON", gender="male")
    names = ["John", "Mark", "Paul", "Steve", "Greg"]
    m1 = [Substitutor(key="k1").substitute("First Name", "PERSON", n, sc) for n in names]
    m2 = [Substitutor(key="k2").substitute("First Name", "PERSON", n, sc) for n in names]
    assert m1 != m2  # key changes the mapping


def test_gender_preserved():
    from proxy.substitute import POOLS
    male = Substitutor(key="k").substitute("First Name", "PERSON", "John", _sc("First Name", "PERSON", gender="male"))
    female = Substitutor(key="k").substitute("First Name", "PERSON", "Lisa", _sc("First Name", "PERSON", gender="female"))
    assert male in POOLS["male"] and female in POOLS["female"]


def test_state_stays_in_region():
    repl = Substitutor(key="k").substitute("State", "LOCATION", "Connecticut", _sc("State", "LOCATION", region="Northeast"))
    assert repl in REGIONS["Northeast"] and repl != "Connecticut"


def test_replacement_differs_from_original():
    s = Substitutor(key="k")
    assert s.substitute("First Name", "PERSON", "John", _sc("First Name", "PERSON", gender="male")) != "John"


def test_oneway_default_keeps_no_store():
    assert Substitutor().store is None
    assert Substitutor(round_trip=True).store is not None


def test_roundtrip_reverse():
    s = Substitutor(key="k", round_trip=True)
    repl = s.substitute("First Name", "PERSON", "John", _sc("First Name", "PERSON", gender="male"))
    assert s.store.reverse("First Name", repl) == "John"


def test_map_encrypt_save_load_reverse(tmp_path):
    s = Substitutor(key="k", round_trip=True)
    repl = s.substitute("Last Name", "PERSON", "Reed", _sc("Last Name", "PERSON"))
    path = tmp_path / "map.enc"
    s.store.save(str(path), fernet_from_secret("map-secret"))
    loaded = MapStore.load(str(path), fernet_from_secret("map-secret"))
    assert loaded.reverse("Last Name", repl) == "Reed"


def test_wrong_secret_fails(tmp_path):
    s = Substitutor(key="k", round_trip=True)
    s.substitute("Last Name", "PERSON", "Reed", _sc("Last Name", "PERSON"))
    path = tmp_path / "map.enc"
    s.store.save(str(path), fernet_from_secret("right"))
    with pytest.raises(InvalidToken):
        MapStore.load(str(path), fernet_from_secret("wrong"))


def test_ttl_expiry(tmp_path):
    s = Substitutor(key="k", round_trip=True)
    s.substitute("Last Name", "PERSON", "Reed", _sc("Last Name", "PERSON"))
    path = tmp_path / "map.enc"
    s.store.save(str(path), fernet_from_secret("s"), ttl_seconds=-1)  # already expired
    with pytest.raises(MapExpired):
        MapStore.load(str(path), fernet_from_secret("s"))
