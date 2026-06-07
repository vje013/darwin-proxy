"""Real-model end-to-end benchmark. Run on a host with en_core_web_lg installed:

    python benchmarks/benchmark_v2.py path/to/data.csv

Prints per-stage throughput (detect, transform, gate, full abstract) so the real
analyzer cost is measured, not the blank-engine stand-in used in the test suite.
"""
import sys
import time

from proxy.cert import generate_key
from proxy.gate import apply_gate_table
from proxy.ingest import read
from proxy.orchestrator import Proxy


def _timed(label, fn, rows):
    t0 = time.perf_counter()
    out = fn()
    dt = time.perf_counter() - t0
    print(f"{label:24s} {dt:8.3f}s  {rows / dt:10.1f} rows/s")
    return out


def main(path):
    table = read(path)
    n = table.n_rows
    print(f"rows: {n}  cols: {len(table.columns)}\n" + "-" * 52)
    px = Proxy(signing_key=generate_key(), k_threshold=5)
    px.detector.analyze_table(table)  # warm
    mapping = _timed("detect", lambda: px.detector.analyze_table(table), n)
    transformed = _timed("transform", lambda: px.transformer.transform_table(table, mapping)[0], n)
    _timed("gate", lambda: apply_gate_table(transformed, mapping=mapping, k_threshold=5), n)
    _timed("abstract (full)", lambda: px.abstract_table(table), n)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python benchmarks/benchmark_v2.py path/to/data.csv")
    main(sys.argv[1])
