"""Phase 5: re-id gate v2. QIs inferred from detection entities (header-agnostic),
configurable, with a trivial-pass guard that refuses to certify when no QIs were
assessed. Model-free."""
import pandas as pd
import pytest
from hypothesis import given, settings, strategies as st

from proxy.gate import (apply_gate_table, infer_qi_config,
                        _identity, _region, _prefix, _year_bucket, _suppress, _band)
from proxy.ingest import Table

STATES = ["Texas", "California", "Ohio", "New York", "Vermont"]
DATES = ["2019-01-01", "2020-06-30", "2021-03-15"]


def test_qi_inferred_from_entities_not_headers():
    # gibberish headers, identified as geo/date by entity
    t = Table(pd.DataFrame({"xq": ["Texas", "Texas", "Ohio", "Ohio"],
                            "zd": ["2020-01-01", "2020-02-01", "2021-01-01", "2021-06-01"]}))
    _out, res = apply_gate_table(t, mapping={"xq": "LOCATION", "zd": "DATE_TIME"}, k_threshold=2)
    assert set(res["quasi_identifiers"]) == {"xq", "zd"}   # by entity, not header name
    assert res["assessed"] is True and res["trivial_pass"] is False


def test_trivial_pass_guard_blocks_silent_pass():
    # the v1 footgun: no geo/date QIs -> v1 would pass with k=len(rows). v2 refuses.
    t = Table(pd.DataFrame({"name": ["a", "b", "c"], "amt": ["1", "2", "3"]}))
    _out, res = apply_gate_table(t, mapping={"name": "PERSON"}, k_threshold=2)
    assert res["assessed"] is False
    assert res["trivial_pass"] is True
    assert res["passed"] is False                 # does NOT silently pass
    assert res["quasi_identifiers"] == []
    assert res["k"] is None and res["reason"]


def test_no_qi_can_be_explicitly_accepted():
    t = Table(pd.DataFrame({"name": ["a", "b"], "amt": ["1", "2"]}))
    _out, res = apply_gate_table(t, mapping={"name": "PERSON"}, k_threshold=2, require_qi=False)
    assert res["passed"] is True and res["assessed"] is False and res["trivial_pass"] is True


def test_generalizes_until_k_and_preserves_rows():
    rows = [{"State": s, "Acq": d} for s, d in
            [("Texas", "2020-01-01"), ("Texas", "2020-02-01"), ("Ohio", "2021-01-01"),
             ("Ohio", "2021-06-01"), ("Texas", "2020-03-01"), ("Ohio", "2021-09-01")]]
    t = Table(pd.DataFrame(rows))
    out, res = apply_gate_table(t, mapping={"State": "LOCATION", "Acq": "DATE_TIME"}, k_threshold=2)
    assert res["passed"] is True and res["k"] >= 2
    assert len(out.df) == 6                        # no rows dropped


def test_explicit_qi_config_extends_inferred():
    # numeric holdings is a QI but undetectable; caller adds it via qi_config
    rows = [{"State": "Texas", "Shares": str(s)} for s in (100, 200, 100, 200, 100, 200)]
    t = Table(pd.DataFrame(rows))
    qi = {"Shares": [_identity, _band(1000), _suppress]}
    _out, res = apply_gate_table(t, mapping={"State": "LOCATION"}, qi_config=qi, k_threshold=2)
    assert "Shares" in res["quasi_identifiers"] and "State" in res["quasi_identifiers"]


def test_non_qi_columns_untouched():
    rows = [{"State": s, "ShareClass": "A"} for s in ["Texas", "Texas", "Ohio", "Ohio"]]
    t = Table(pd.DataFrame(rows))
    out, _res = apply_gate_table(t, mapping={"State": "LOCATION"}, k_threshold=2)
    assert list(out.df["ShareClass"]) == ["A", "A", "A", "A"]   # signal column preserved


@given(pairs=st.lists(st.tuples(st.sampled_from(STATES), st.sampled_from(DATES)),
                      min_size=1, max_size=60))
@settings(max_examples=80, deadline=None)
def test_gate_invariant_passed_implies_k(pairs):
    df = pd.DataFrame([{"State": s, "Acq": d} for s, d in pairs])
    t = Table(df)
    out, res = apply_gate_table(t, mapping={"State": "LOCATION", "Acq": "DATE_TIME"}, k_threshold=3)
    assert len(out.df) == len(df)                  # row count invariant
    assert res["assessed"] is True
    if res["passed"]:
        assert res["k"] >= 3                       # passed implies achieved k


def test_infer_qi_config_maps_entities():
    qi = infer_qi_config({"a": "LOCATION", "b": "DATE_TIME", "c": "US_SSN"})
    assert "a" in qi and "b" in qi and "c" not in qi   # only geo/date become QIs
