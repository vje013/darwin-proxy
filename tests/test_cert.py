"""Phase 3 exit: Ed25519 certificate, tamper-evidence, and trust-root split."""

from proxy.schemas import AbstractionManifest
from proxy import cert


def _manifest():
    return AbstractionManifest(records=500, before_hash="aa", after_hash="bb",
                               gate_result={"k": 8, "passed": True})


def test_sign_then_verify_self():
    m = _manifest()
    cert.sign_manifest(m, cert.generate_key())
    r = cert.verify_manifest(m)
    assert r["valid"] and r["root"] == "self"


def test_darwin_root_recognized():
    m = _manifest()
    k = cert.generate_key()
    cert.sign_manifest(m, k)
    r = cert.verify_manifest(m, darwin_root=cert._pubkey_hex(k))
    assert r["valid"] and r["root"] == "darwin"


def test_tamper_breaks_signature():
    m = _manifest()
    cert.sign_manifest(m, cert.generate_key())
    m.records = 499  # tamper after signing
    assert cert.verify_manifest(m)["valid"] is False


def test_unsigned_is_none():
    r = cert.verify_manifest(_manifest())
    assert r["valid"] is False and r["root"] == "none"


def test_json_roundtrip_still_valid():
    m = _manifest()
    cert.sign_manifest(m, cert.generate_key())
    m2 = AbstractionManifest.model_validate_json(m.model_dump_json())
    assert cert.verify_manifest(m2)["valid"] is True
