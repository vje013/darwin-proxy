"""Canonical in-memory table. All cells are strings, missing values are "",
so a redaction pipeline never sees a coerced int, a float "123.0", or a NaN."""
from dataclasses import dataclass

import pandas as pd


def stringify(df):
    """Coerce every column to string, NaN/None to "". Integer-valued float
    columns (common from Excel/Parquet/SQL) render without a trailing .0."""
    out = df.copy()
    for c in out.columns:
        s = out[c]
        if pd.api.types.is_float_dtype(s) and s.notna().any() and \
                s.dropna().apply(lambda x: float(x).is_integer()).all():
            out[c] = s.apply(lambda x: "" if pd.isna(x) else str(int(x)))
        else:
            out[c] = s.apply(lambda x: "" if (x is None or (isinstance(x, float) and pd.isna(x))) else str(x))
    return out


@dataclass
class Table:
    df: pd.DataFrame
    source_format: str = "dataframe"

    def __post_init__(self):
        self.df = stringify(self.df)

    @property
    def columns(self):
        return list(self.df.columns)

    @property
    def n_rows(self):
        return len(self.df)

    def rows(self):
        for rec in self.df.to_dict(orient="records"):
            yield rec

    def to_rows(self):
        return self.df.to_dict(orient="records")

    def chunks(self, size):
        if size <= 0:
            raise ValueError("chunk size must be positive")
        for i in range(0, len(self.df), size):
            yield Table(self.df.iloc[i:i + size].reset_index(drop=True), self.source_format)
