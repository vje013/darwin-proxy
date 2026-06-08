"""Phase 7: certificate v2. The signature binds the full abstraction context;
re-check verifies the re-checkable claims (authenticity, output integrity,
k-anonymity recomputed from the output) and reports the unprovable ones honestly,
never claiming k-anonymity the gate did not assess."""
import pandas as pd

from proxy.cert import _pubkey_hex, generate_key, sign_manifest
from proxy.certify import build_manifest, recheck
from proxy.ingest import Table


def _out(states):
    return Table(pd.DataFrame({"email": [f"u{i}@e.com" for i in range(len(states))],
                               "State": states}))


def _manifest(gate, after, before=None):
    before = before or after
    return build_manifest(records=len(after.df), detection={"email": "EMAIL_ADDRESS", "State": "LOCATION"},
                          kept_columns=["State"], operators={"EMAIL_ADDRESS": "keyed_substitute"},
                          reversibility="map", gate_result=gate, before_table=before, after_table=after)


def _gate(k, thr=2, assessed=True, qis=("State",), reason=None, trivial=False):
    return {"k": k, "threshold": thr, "passed": (assessed and k is not None and k >= thr),
            "assessed": assessed, "trivial_pass": trivial,
            "quasi_identifiers": list(qis), "generalized": {}, "reason": reason}


def test_sign_and_recheck_valid():
    out = _out(["South", "South", "North", "North"])
    m = _manifest(_gate(2), out)
    sign_manifest(m, generate_key())
    r = recheck(m, out)
    assert r["valid"] is True
    assert r["schema_version"] == 2
    assert r["signature"]["root"] == "self"
    assert r["k_anonymity"]["certified"] is True and r["k_anonymity"]["recomputed_k"] == 2


def test_tampered_output_breaks_integrity():
    out = _out(["South", "South", "North", "North"])
    m = _manifest(_gate(2), out)
    sign_manifest(m, generate_key())
    tampered = Table(pd.DataFrame({"email": ["X", "X", "X", "X"], "State": ["South", "South", "North", "North"]}))
    r = recheck(m, tampered)
    assert r["integrity"]["output_hash_matches"] is False
    assert r["valid"] is False


def test_tampered_manifest_breaks_signature():
    out = _out(["South", "South"])
    m = _manifest(_gate(2), out)
    sign_manifest(m, generate_key())
    m.records = 999                      # mutate a bound field after signing
    r = recheck(m, out)
    assert r["signature"]["valid"] is False and r["valid"] is False


def test_darwin_root_recognized():
    out = _out(["South", "South"])
    m = _manifest(_gate(2), out)
    key = generate_key()
    sign_manifest(m, key)
    r = recheck(m, out, darwin_root=_pubkey_hex(key))
    assert r["signature"]["root"] == "darwin"


def test_recheck_catches_k_overclaim():
    # output is actually k=1 over State (all unique); manifest lies that k=5
    out = _out(["A", "B", "C", "D"])
    m = _manifest(_gate(5, thr=5), out)
    sign_manifest(m, generate_key())
    r = recheck(m, out)
    assert r["signature"]["valid"] is True       # authentic signature
    assert r["k_anonymity"]["certified"] is False  # but the claim fails independent re-check
    assert r["k_anonymity"]["recomputed_k"] == 1
    assert r["k_anonymity"]["matches_claim"] is False


def test_unassessed_gate_not_certified_but_authentic():
    out = _out(["South", "South"])
    m = _manifest(_gate(None, assessed=False, qis=(), reason="no quasi-identifiers identified"), out)
    sign_manifest(m, generate_key())
    r = recheck(m, out)
    assert r["valid"] is True                     # integrity holds
    assert r["k_anonymity"]["assessed"] is False
    assert r["k_anonymity"]["certified"] is False
    assert r["k_anonymity"]["reason"]


def test_deid_note_is_mode_aware():
    out = _out(["South", "South"])
    m = _manifest(_gate(2), out)
    sign_manifest(m, generate_key())
    assert "authority judgment" in recheck(m, out)["deidentification"]["note"]


def test_deid_note_encrypt_mode_is_opaque():
    out = _out(["South", "South"])
    m = build_manifest(records=2, detection={"email": "EMAIL_ADDRESS"}, kept_columns=[],
                       operators={"EMAIL_ADDRESS": "encrypt"}, reversibility="encrypt",
                       gate_result=_gate(2), before_table=out, after_table=out)
    sign_manifest(m, generate_key())
    note = recheck(m, out)["deidentification"]["note"]
    assert "not recoverable" in note and "without the key" in note
