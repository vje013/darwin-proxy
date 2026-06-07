"""Phase 9: property/fuzz sweep. Cross-format ingest fidelity and a multi-entity
no-PII-survives property over the transform layer."""
import csv as _csv

import pandas as pd
from hypothesis import given, settings, strategies as st

from proxy.ingest import Table, read
from proxy.transform import Transformer

_TR = Transformer(key="fuzz")
_cell = st.text(alphabet=st.characters(blacklist_categories=("Cs", "Cc")), min_size=0, max_size=12)


@given(rows=st.lists(st.tuples(_cell, _cell), min_size=1, max_size=30))
@settings(max_examples=50, deadline=None)
def test_csv_json_ingest_agree(rows, tmp_path_factory):
    d = tmp_path_factory.mktemp("fuzz")
    df = pd.DataFrame(rows, columns=["a", "b"])
    csv_p, json_p = d / "t.csv", d / "t.json"
    df.to_csv(csv_p, index=False, quoting=_csv.QUOTE_ALL)
    df.to_json(json_p, orient="records")
    a, b = read(str(csv_p)), read(str(json_p))
    assert a.df.shape == b.df.shape and list(a.df["a"]) == list(b.df["a"])


@given(emails=st.lists(st.emails(), min_size=1, max_size=20),
       ssns=st.lists(st.from_regex(r"[0-9]{3}-[0-9]{2}-[0-9]{4}", fullmatch=True), min_size=1, max_size=20))
@settings(max_examples=50, deadline=None)
def test_no_identifier_survives_multientity(emails, ssns):
    n = min(len(emails), len(ssns))
    t = Table(pd.DataFrame({"email": emails[:n], "ssn": ssns[:n]}))
    out, _ = _TR.transform_table(t, {"email": "EMAIL_ADDRESS", "ssn": "US_SSN"})
    for col, src in (("email", emails[:n]), ("ssn", ssns[:n])):
        got = list(out.df[col])
        assert all(got[i] != src[i] for i in range(n))        # every cell replaced in place
