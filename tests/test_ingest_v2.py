"""Phase 1: universal input layer. Every format normalizes to a Table; every
malformed input maps to a typed InputError, never an uncaught exception."""
import json

import pandas as pd
import pytest
from hypothesis import given, settings, strategies as st

from proxy.ingest import read, read_chunks, read_records, read_sql, InputError, Table


def _write(path, text, encoding="utf-8"):
    path.write_text(text, encoding=encoding)
    return str(path)


# ---- happy paths per format ----------------------------------------------

def test_csv_string_fidelity(tmp_path):
    p = _write(tmp_path / "a.csv", "id,acct,amount\n001,0071234567,16249\n002,0089991234,39024\n")
    t = read(p)
    assert t.columns == ["id", "acct", "amount"]
    assert t.to_rows()[0]["id"] == "001"          # leading zeros preserved
    assert t.to_rows()[0]["acct"] == "0071234567"  # no int coercion
    assert t.source_format == "csv"


def test_json_records(tmp_path):
    p = _write(tmp_path / "a.json", json.dumps([{"name": "John", "email": "j@x.com"}]))
    t = read(p)
    assert t.columns == ["name", "email"] and t.n_rows == 1


def test_json_nested_flattens(tmp_path):
    p = _write(tmp_path / "n.json", json.dumps([{"name": "John", "addr": {"city": "Reno"}}]))
    t = read(p)
    assert "addr.city" in t.columns and t.to_rows()[0]["addr.city"] == "Reno"


def test_excel_roundtrip(tmp_path):
    pytest.importorskip("openpyxl")
    p = tmp_path / "a.xlsx"
    pd.DataFrame({"name": ["John"], "shares": [16249]}).to_excel(p, index=False)
    t = read(str(p))
    assert t.to_rows()[0]["shares"] == "16249"  # int rendered without .0


def test_parquet_roundtrip(tmp_path):
    pytest.importorskip("pyarrow")
    p = tmp_path / "a.parquet"
    pd.DataFrame({"name": ["John"], "shares": [16249]}).to_parquet(p)
    t = read(str(p))
    assert t.to_rows()[0]["shares"] == "16249"


def test_sql_read():
    sa = pytest.importorskip("sqlalchemy")
    eng = sa.create_engine("sqlite:///:memory:")
    with eng.begin() as con:
        con.exec_driver_sql("create table h (name text, shares int)")
        con.exec_driver_sql("insert into h values ('John', 16249)")
    t = read_sql("select * from h", eng)
    assert t.to_rows()[0]["shares"] == "16249"


def test_records_in_memory():
    t = read_records([{"a": "1"}, {"a": "2"}])
    assert t.n_rows == 2


# ---- robustness: malformed -> typed error ---------------------------------

def test_empty_file_errors(tmp_path):
    with pytest.raises(InputError) as e:
        read(_write(tmp_path / "e.csv", ""))
    assert e.value.kind == "empty"


def test_header_only_is_valid_empty_table(tmp_path):
    t = read(_write(tmp_path / "h.csv", "a,b,c\n"))
    assert t.n_rows == 0 and t.columns == ["a", "b", "c"]


def test_ragged_overfilled_errors(tmp_path):
    with pytest.raises(InputError):
        read(_write(tmp_path / "r.csv", "a,b,c\n1,2,3\n4,5,6,7,8\n"))


def test_unknown_format_errors(tmp_path):
    with pytest.raises(InputError) as e:
        read(_write(tmp_path / "x.weird", "data"))
    assert e.value.kind == "unknown_format"


def test_not_found_errors():
    with pytest.raises(InputError) as e:
        read("/nonexistent/file.csv")
    assert e.value.kind == "not_found"


def test_bad_json_errors(tmp_path):
    with pytest.raises(InputError):
        read(_write(tmp_path / "b.json", "{not valid json"))


# ---- chunking -------------------------------------------------------------

def test_chunks_cover_all_rows(tmp_path):
    rows = "\n".join(f"{i},x" for i in range(25))
    p = _write(tmp_path / "big.csv", "id,v\n" + rows + "\n")
    chunks = list(read_chunks(p, size=10))
    assert sum(c.n_rows for c in chunks) == 25 and len(chunks) == 3


# ---- property: round-trip fidelity ----------------------------------------

_safe = st.text(alphabet=st.characters(blacklist_categories=("Cc", "Cs"),
                                       blacklist_characters=',"\n\r'), min_size=0, max_size=12)


@settings(max_examples=60, deadline=None)
@given(st.lists(st.fixed_dictionaries({"a": _safe, "b": _safe}), min_size=1, max_size=20))
def test_csv_roundtrip_fidelity(records):
    import os
    import tempfile
    df = pd.DataFrame(records)
    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    try:
        df.to_csv(path, index=False)
        back = read(path).to_rows()
    finally:
        os.remove(path)
    assert back == [{"a": r["a"], "b": r["b"]} for r in records]


# ---- fuzz: the seed corpus never crashes the readers ----------------------

def test_fuzz_corpus_no_uncaught(run_fuzz, corpus_files):
    def target(f):
        try:
            read(str(f))
        except InputError:
            pass  # typed error is the acceptable outcome
    assert run_fuzz(target, corpus_files) == []


# ---- perf -----------------------------------------------------------------

@pytest.mark.perf
def test_read_perf(tmp_path, perf_check):
    import time
    rows = "\n".join(f"{i},John,Vermont,{1000+i}" for i in range(5000))
    p = _write(tmp_path / "perf.csv", "id,name,state,shares\n" + rows + "\n")
    t0 = time.perf_counter()
    n = read(p).n_rows
    dt = time.perf_counter() - t0
    perf_check.check("csv_read_rows_per_sec", n / dt, higher_is_better=True)


# ---- additional branch coverage for the new layer ------------------------

def test_encoding_error(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_bytes(b"name\nJos\xe9\n")  # latin-1 e-acute, invalid as utf-8
    with pytest.raises(InputError) as e:
        read(str(p))
    assert e.value.kind == "encoding"


def test_explicit_fmt_override(tmp_path):
    p = tmp_path / "data.txt"
    p.write_text("a,b\n1,2\n")
    t = read(str(p), fmt="csv")
    assert t.columns == ["a", "b"]


def test_json_scalar_rejected(tmp_path):
    p = tmp_path / "s.json"
    p.write_text("42")
    with pytest.raises(InputError):
        read(str(p))


def test_read_dataframe_empty_errors():
    with pytest.raises(InputError) as e:
        from proxy.ingest import read_dataframe
        read_dataframe(pd.DataFrame())
    assert e.value.kind == "empty"


def test_read_records_empty_errors():
    with pytest.raises(InputError):
        read_records([])


def test_read_sql_bad_query():
    sa = pytest.importorskip("sqlalchemy")
    eng = sa.create_engine("sqlite:///:memory:")
    with pytest.raises(InputError):
        read_sql("select * from does_not_exist", eng)


def test_table_chunk_size_validation():
    t = read_records([{"a": "1"}])
    with pytest.raises(ValueError):
        list(t.chunks(0))


def test_read_chunks_nonstreaming_format(tmp_path):
    pytest.importorskip("pyarrow")
    p = tmp_path / "c.parquet"
    pd.DataFrame({"a": [1, 2, 3]}).to_parquet(p)
    chunks = list(read_chunks(str(p), size=2))
    assert sum(c.n_rows for c in chunks) == 3


def test_read_chunks_empty_csv(tmp_path):
    p = tmp_path / "e.csv"
    p.write_text("")
    with pytest.raises(InputError):
        list(read_chunks(str(p)))


def test_stringify_float_passthrough():
    t = Table(pd.DataFrame({"x": [1.5, 2.0, None]}))
    rows = t.to_rows()
    assert rows[0]["x"] == "1.5" and rows[2]["x"] == ""  # non-integer floats kept, NaN -> ""
