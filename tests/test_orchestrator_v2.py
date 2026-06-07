"""Phase 8a: v2 orchestrator. ingest -> detect -> transform -> gate -> certify in
one call. Model-free via the blank engine, signing with a generated key."""
import json

import pandas as pd
import pytest
import spacy
from presidio_analyzer.nlp_engine import SpacyNlpEngine

from proxy.cert import generate_key
from proxy.certify import recheck
from proxy.ingest import Table
from proxy.orchestrator import Proxy


class _Blank(SpacyNlpEngine):
    def __init__(self):
        super().__init__(models=[{"lang_code": "en", "model_name": "en_core_web_lg"}])
        self.nlp = {"en": spacy.blank("en")}


def _proxy(**kw):
    return Proxy(nlp_engine=_Blank(), signing_key=generate_key(), k_threshold=2, **kw)


def _table():
    return Table(pd.DataFrame({
        "email": ["a@x.com", "b@y.com", "a@x.com", "c@z.com"],
        "ssn": ["123-45-6789", "987-65-4320", "123-45-6789", "111-22-3333"],
        "state": ["Texas", "Texas", "Ohio", "Ohio"],
        "shares": ["100", "200", "300", "400"],
    }))


def test_abstract_table_end_to_end_and_recheck():
    out, manifest = _proxy(key="K").abstract_table(
        _table(), reversibility="oneway",
        override={"state": "LOCATION"})           # pin geography as QI (blank engine has no NER)
    assert "a@x.com" not in set(out.df["email"])  # identifiers substituted
    assert manifest.detection["email"] == "EMAIL_ADDRESS"
    assert manifest.operators["EMAIL_ADDRESS"] == "keyed_substitute"
    assert manifest.reversibility == "oneway"
    assert "state" in manifest.kept_columns and "shares" in manifest.kept_columns
    r = recheck(manifest, out)
    assert r["valid"] is True and r["signature"]["root"] == "self"


def test_map_mode_round_trips_identifiers():
    px = _proxy(key="K", round_trip=True)
    t = _table()
    out, manifest = px.abstract_table(t, reversibility="map", override={"state": "LOCATION"})
    back = px.reverse_table(out, manifest)
    assert list(back.df["email"]) == ["a@x.com", "b@y.com", "a@x.com", "c@z.com"]
    assert list(back.df["ssn"])[0] == "123-45-6789"


def test_encrypt_mode_opaque_and_certified():
    out, manifest = _proxy(key="K").abstract_table(_table(), reversibility="encrypt",
                                                   override={"state": "LOCATION"})
    assert "@" not in out.df["email"][0]               # opaque
    assert manifest.operators["EMAIL_ADDRESS"] == "encrypt"
    assert recheck(manifest, out)["valid"] is True


def test_gate_generalizes_and_recheck_confirms_k():
    out, manifest = _proxy(key="K").abstract_table(_table(), override={"state": "LOCATION"})
    g = manifest.gate
    assert g["assessed"] is True
    r = recheck(manifest, out)
    assert r["k_anonymity"]["certified"] is True
    assert r["k_anonymity"]["recomputed_k"] >= 2


def test_trivial_pass_when_no_qi():
    # no override, blank engine detects no geography -> no QI -> guarded, not silent pass
    out, manifest = _proxy(key="K").abstract_table(_table())
    assert manifest.gate["assessed"] is False
    assert manifest.gate["trivial_pass"] is True
    assert recheck(manifest, out)["k_anonymity"]["certified"] is False


def test_abstract_file_writes_output_and_manifest(tmp_path):
    src = tmp_path / "in.csv"
    _table().df.to_csv(src, index=False)
    out_path = str(tmp_path / "out.csv")
    written, manifest = _proxy(key="K").abstract_file(str(src), out_path, override={"state": "LOCATION"})
    assert written == out_path
    assert (tmp_path / "out.csv").exists()
    sidecar = tmp_path / "out.csv.manifest.json"
    assert sidecar.exists()
    loaded = json.loads(sidecar.read_text())
    assert loaded["schema_version"] == 2 and loaded["signature"]


def test_unsigned_when_sign_false():
    out, manifest = _proxy(key="K").abstract_table(_table(), sign=False)
    assert manifest.signature == "" and manifest.signer_pubkey == ""
