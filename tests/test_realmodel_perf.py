"""Phase 9: real-model benchmark. Every other perf number is blank-engine; this
times the full abstraction with the real spaCy model. It skips where the model is
absent (sandbox/CI) and runs on the host, seeding a host-local baseline."""
import time

import pandas as pd
import pytest
import spacy.util

from proxy.cert import generate_key
from proxy.ingest import Table
from proxy.orchestrator import Proxy

requires_model = pytest.mark.skipif(
    not spacy.util.is_package("en_core_web_lg"), reason="needs en_core_web_lg (host only)")


@pytest.mark.perf
@requires_model
def test_realmodel_abstract_throughput(perf_check):
    n = 200
    t = Table(pd.DataFrame({
        "email": [f"u{i}@x.com" for i in range(n)],
        "name": ["John Smith"] * n,
        "state": ["Texas"] * n,
    }))
    px = Proxy(signing_key=generate_key(), k_threshold=2)
    px.detector.analyze_table(Table(pd.DataFrame({"email": ["w@x.com"]})))  # warm the analyzer
    t0 = time.perf_counter()
    px.abstract_table(t, require_qi=False)
    rate = n / (time.perf_counter() - t0)
    perf_check.check("abstract_realmodel_rows_per_sec", rate, higher_is_better=True)
