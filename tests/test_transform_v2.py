"""Phase 3: transform layer. Keyed signal-preserving substitution as a custom
operator, plus the commodity operators, plus the no-PII-survives guarantee.
Model-free: transforms take an explicit mapping, so no analyzer is needed here
(detection is proven in Phase 2)."""
import pandas as pd
import pytest
from hypothesis import given, settings, strategies as st
from presidio_anonymizer import OperatorConfig

from proxy.ingest import Table
from proxy.transform import Transformer

# pools build once; deterministic given the key
_TR = Transformer(key="prop-key")


def _df(**cols):
    return Table(pd.DataFrame(cols))


@pytest.fixture(scope="module")
def tr():
    return Transformer(key="test-key")


def test_keyed_substitution_replaces_and_shapes(tr):
    out, mapped = tr.transform_table(
        _df(email=["a@x.com", "b@y.com"], ssn=["123-45-6789", "987-65-4320"]),
        {"email": "EMAIL_ADDRESS", "ssn": "US_SSN"})
    assert mapped == {"email": "EMAIL_ADDRESS", "ssn": "US_SSN"}
    assert "a@x.com" not in set(out.df["email"])
    assert out.df["email"][0].endswith("@example.com")        # still email-shaped
    assert len(out.df["ssn"][0]) == 11 and out.df["ssn"][0][3] == "-"  # SSN-shaped


def test_referential_consistency_across_rows(tr):
    out, _ = tr.transform_table(
        _df(email=["dup@x.com", "other@x.com", "dup@x.com"]), {"email": "EMAIL_ADDRESS"})
    assert out.df["email"][0] == out.df["email"][2]   # same input -> same token
    assert out.df["email"][0] != out.df["email"][1]


def test_consistency_across_columns(tr):
    # same value, same entity type, different columns -> same token (joins survive)
    out, _ = tr.transform_table(
        _df(primary=["shared@x.com"], secondary=["shared@x.com"]),
        {"primary": "EMAIL_ADDRESS", "secondary": "EMAIL_ADDRESS"})
    assert out.df["primary"][0] == out.df["secondary"][0]


def test_wrong_key_changes_output():
    rows = _df(email=["a@x.com"])
    a = Transformer(key="key-A").transform_table(rows, {"email": "EMAIL_ADDRESS"})[0]
    b = Transformer(key="key-B").transform_table(rows, {"email": "EMAIL_ADDRESS"})[0]
    assert a.df["email"][0] != b.df["email"][0]


def test_same_key_is_deterministic_across_runs():
    rows = _df(email=["a@x.com", "b@y.com"])
    a = Transformer(key="same").transform_table(rows, {"email": "EMAIL_ADDRESS"})[0]
    b = Transformer(key="same").transform_table(rows, {"email": "EMAIL_ADDRESS"})[0]
    assert list(a.df["email"]) == list(b.df["email"])


def test_quasi_identifiers_pass_through(tr):
    out, mapped = tr.transform_table(
        _df(state=["Texas", "Ohio"], acq=["2021-01-01", "2022-06-30"], email=["a@x.com", "b@y.com"]),
        {"state": "LOCATION", "acq": "DATE_TIME", "email": "EMAIL_ADDRESS"})
    assert "state" not in mapped and "acq" not in mapped   # kept for the gate
    assert list(out.df["state"]) == ["Texas", "Ohio"]
    assert list(out.df["acq"]) == ["2021-01-01", "2022-06-30"]
    assert "a@x.com" not in set(out.df["email"])            # identifier still transformed


def test_commodity_operators_reachable(tr):
    rows = _df(email=["a@x.com", "b@y.com"])
    redacted = tr.transform_table(rows, {"email": "EMAIL_ADDRESS"},
                                  operators={"EMAIL_ADDRESS": OperatorConfig("redact", {})})[0]
    assert all(v == "" for v in redacted.df["email"])
    replaced = tr.transform_table(rows, {"email": "EMAIL_ADDRESS"},
                                  operators={"EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<X>"})})[0]
    assert all(v == "<X>" for v in replaced.df["email"])
    hashed = tr.transform_table(rows, {"email": "EMAIL_ADDRESS"},
                                operators={"EMAIL_ADDRESS": OperatorConfig("hash", {"hash_type": "sha256"})})[0]
    assert all(len(v) == 64 for v in hashed.df["email"])   # sha256 hex


@given(emails=st.lists(st.emails(), min_size=1, max_size=25))
@settings(max_examples=60, deadline=None)
def test_no_pii_survives_in_place(emails):
    out, _ = _TR.transform_table(_df(e=emails), {"e": "EMAIL_ADDRESS"})
    got = list(out.df["e"])
    # every original cell value is replaced
    assert all(got[i] != emails[i] for i in range(len(emails)))
    # and substitution is consistent: equal inputs -> equal outputs
    for i in range(len(emails)):
        for j in range(len(emails)):
            if emails[i] == emails[j]:
                assert got[i] == got[j]


def test_transform_golden(tr, golden):
    out, _ = tr.transform_table(
        _df(email=["a@x.com", "b@y.com"], ssn=["123-45-6789", "987-65-4320"]),
        {"email": "EMAIL_ADDRESS", "ssn": "US_SSN"})
    golden.check("phase3_transform", {c: list(out.df[c]) for c in out.df.columns})


def test_transform_cell_narrative(tr):
    from presidio_anonymizer.entities import RecognizerResult
    text = "client SSN is 123-45-6789 today"
    results = [RecognizerResult(entity_type="US_SSN", start=14, end=25, score=1.0)]
    out = tr.transform_cell(text, results)
    assert "123-45-6789" not in out      # identifier gone
    assert out.startswith("client SSN is") and out.endswith("today")  # context preserved


def test_empty_mapping_is_noop(tr):
    rows = _df(x=["1", "2"], y=["a", "b"])
    out, mapped = tr.transform_table(rows, {})
    assert mapped == {}
    assert list(out.df["x"]) == ["1", "2"] and list(out.df["y"]) == ["a", "b"]


@pytest.mark.perf
def test_transform_perf(tr, perf_check):
    import time
    n = 2000
    rows = _df(email=[f"u{i}@x.com" for i in range(n)], ssn=["123-45-6789"] * n)
    t0 = time.perf_counter()
    tr.transform_table(rows, {"email": "EMAIL_ADDRESS", "ssn": "US_SSN"})
    perf_check.check("transform_rows_per_sec", n / (time.perf_counter() - t0), higher_is_better=True)
