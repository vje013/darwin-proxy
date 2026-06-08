"""Detection throughput sweep (P0 of the throughput plan).

Run on a host with en_core_web_lg installed (en_core_web_sm optional):

    python benchmarks/bench_detection.py [rows]   # default 2000

Times the detection step under each lever and prints a rows/s comparison table,
so the later phases optimize against evidence. No production code is changed; this
calls PandasAnalysisBuilder directly with the knobs Presidio already exposes.
Configurations whose model is not installed report n/a rather than failing.
"""
import random
import sys
import time

import pandas as pd
import spacy
import spacy.util
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_structured import PandasAnalysisBuilder

from proxy.detection.engine import build_analyzer


def make_table(n):
    random.seed(1729)
    return pd.DataFrame({
        "email": [f"u{i}@x.com" for i in range(n)],
        "name": [random.choice(["John Smith", "Jane Doe", "Robert Lee"]) for _ in range(n)],
        "state": [random.choice(["Texas", "Ohio", "Vermont", "California"]) for _ in range(n)],
        "ssn": ["123-45-6789"] * n,
        "shares": [str(random.randint(1, 99999)) for _ in range(n)],
    })


def _blank_engine():
    class Blank(SpacyNlpEngine):
        def __init__(self):
            super().__init__(models=[{"lang_code": "en", "model_name": "en_core_web_lg"}])
            self.nlp = {"en": spacy.blank("en")}
    return Blank()


def _analyzer(model=None, ner=True):
    if not ner:
        return build_analyzer(nlp_engine=_blank_engine())
    name = model or "en_core_web_lg"
    if not spacy.util.is_package(name):
        return None
    return build_analyzer(model=name)


def _time(df, analyzer, batch_size=1, n_process=1, n=None):
    if analyzer is None:
        return None
    try:
        b = PandasAnalysisBuilder(analyzer=analyzer, batch_size=batch_size, n_process=n_process)
        b.generate_analysis(df.head(min(len(df), 16)))            # warm
        t0 = time.perf_counter()
        mapping = b.generate_analysis(df, n=n)
        dt = time.perf_counter() - t0
        return len(df) / dt, dict(mapping.entity_mapping)
    except Exception as e:  # noqa: BLE001 - record, do not abort the sweep
        return ("error", str(e)[:40])


def main(n_rows):
    df = make_table(n_rows)
    lg = _analyzer(ner=True)                  # default lg
    sm = _analyzer(model="en_core_web_sm", ner=True)
    blank = _analyzer(ner=False)

    configs = [
        ("baseline lg b1 p1 all", lg, 1, 1, None),
        ("lg b16 p1 all", lg, 16, 1, None),
        ("lg b32 p1 all", lg, 32, 1, None),
        ("lg b64 p1 all", lg, 64, 1, None),
        ("lg b32 p2 all", lg, 32, 2, None),
        ("lg b32 p4 all", lg, 32, 4, None),
        ("lg b32 p1 sample200", lg, 32, 1, 200),
        ("lg b32 p1 sample500", lg, 32, 1, 500),
        ("sm b32 p1 all", sm, 32, 1, None),
        ("no-ner (pattern) b32", blank, 32, 1, None),
    ]
    print(f"rows: {n_rows}\n" + "=" * 60)
    print(f"{'config':28s} {'rows/s':>12s}  mapping/notes")
    print("-" * 60)
    for label, an, bs, npr, n in configs:
        res = _time(df, an, batch_size=bs, n_process=npr, n=n)
        if res is None:
            print(f"{label:28s} {'n/a':>12s}  (model not installed)")
        elif res[0] == "error":
            print(f"{label:28s} {'error':>12s}  {res[1]}")
        else:
            rate, mapping = res
            print(f"{label:28s} {rate:12.1f}  {mapping}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 2000)
