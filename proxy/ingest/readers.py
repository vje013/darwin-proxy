"""Universal readers. Every supported format normalizes to a Table, and every
failure mode raises a typed InputError. No raw parser exception escapes.

Fidelity: CSV and JSON are read as strings with no type coercion. Excel, Parquet,
and SQL carry native types and are stringified on the way into the Table, which
can normalize numeric formatting.
"""
import json
import os
import pathlib

import pandas as pd

from proxy.ingest.table import Table

_EXT = {".csv": "csv", ".tsv": "csv", ".xlsx": "excel", ".xls": "excel",
        ".parquet": "parquet", ".json": "json"}


class InputError(Exception):
    def __init__(self, message, kind="invalid"):
        super().__init__(message)
        self.kind = kind


def _infer(path):
    return _EXT.get(pathlib.Path(str(path)).suffix.lower())


def read(path, fmt=None, encoding="utf-8-sig"):
    fmt = fmt or _infer(path)
    if fmt is None:
        raise InputError(f"unknown format for {path}", "unknown_format")
    try:
        if fmt == "csv":
            if os.path.getsize(path) == 0:
                raise InputError("empty file", "empty")
            df = pd.read_csv(path, dtype=str, keep_default_na=False,
                             encoding=encoding, on_bad_lines="error")
        elif fmt == "excel":
            df = _read_excel(path)
        elif fmt == "parquet":
            df = _read_parquet(path)
        elif fmt == "json":
            df = _read_json(path, encoding)
        else:
            raise InputError(f"unsupported format {fmt}", "unsupported")
    except InputError:
        raise
    except FileNotFoundError:
        raise InputError(f"file not found: {path}", "not_found")
    except UnicodeDecodeError:
        raise InputError("cannot decode input as " + encoding, "encoding")
    except Exception as e:  # noqa: BLE001 - normalize any parser failure
        raise InputError(f"cannot parse {fmt}: {e}", "parse")
    if df is None or df.shape[1] == 0:
        raise InputError("no columns parsed (empty or non-tabular input)", "empty")
    return Table(df, fmt)


def _read_excel(path):
    try:
        import openpyxl  # noqa: F401
    except ImportError:
        raise InputError("excel support needs openpyxl (pip install darwin-proxy[formats])", "missing_dep")
    return pd.read_excel(path, dtype=str)


def _read_parquet(path):
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        raise InputError("parquet support needs pyarrow (pip install darwin-proxy[formats])", "missing_dep")
    return pd.read_parquet(path)


def _read_json(path, encoding):
    with open(path, encoding=encoding) as f:
        data = json.load(f)
    if isinstance(data, list):
        if not data:
            raise InputError("empty JSON array", "empty")
        return pd.json_normalize(data)
    if isinstance(data, dict):
        return pd.json_normalize([data])
    raise InputError("JSON must be an object or an array of objects", "parse")


def read_dataframe(df, source_format="dataframe"):
    if df is None or len(df.columns) == 0:
        raise InputError("empty dataframe", "empty")
    return Table(df, source_format)


def read_records(records, source_format="records"):
    if not records:
        raise InputError("no records", "empty")
    return Table(pd.json_normalize(records), source_format)


def read_sql(query, con, source_format="sql"):
    try:
        df = pd.read_sql(query, con)
    except Exception as e:  # noqa: BLE001
        raise InputError(f"sql read failed: {e}", "parse")
    return Table(df, source_format)


def read_chunks(path, fmt=None, size=10000, encoding="utf-8-sig"):
    fmt = fmt or _infer(path)
    if fmt == "csv":
        if os.path.getsize(path) == 0:
            raise InputError("empty file", "empty")
        try:
            reader = pd.read_csv(path, dtype=str, keep_default_na=False,
                                 encoding=encoding, on_bad_lines="error", chunksize=size)
            for chunk in reader:
                yield Table(chunk.reset_index(drop=True), "csv")
        except InputError:
            raise
        except Exception as e:  # noqa: BLE001
            raise InputError(f"cannot parse csv: {e}", "parse")
    else:
        yield from read(path, fmt, encoding).chunks(size)
