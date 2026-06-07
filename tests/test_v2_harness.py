"""Phase 0 meta-tests: prove each quality gate runs AND is capable of failing.
If these pass, the harness can catch regressions in later phases."""
import random
import time

import pytest


# ---- golden gate ----------------------------------------------------------

def test_golden_roundtrip(golden):
    golden.check("phase0_sample_mapping", {"name": "PERSON", "email": "EMAIL_ADDRESS"})


def test_golden_detects_mismatch(golden):
    assert golden.compare({"a": 1}, {"a": 1}) is True
    assert golden.compare({"a": 1}, {"a": 2}) is False  # gate CAN fail


# ---- perf gate ------------------------------------------------------------

def test_perf_gate_detects_regression(perf_check):
    assert perf_check.evaluate(1000, 900, higher_is_better=True, band=0.3) is True
    assert perf_check.evaluate(1000, 500, higher_is_better=True, band=0.3) is False  # 50% slower fails
    assert perf_check.evaluate(10, 25, higher_is_better=False, band=0.3) is False    # latency regression fails


@pytest.mark.perf
def test_perf_real_microbench(perf_check):
    from proxy.gate import apply_gate
    rows = [{"State": random.choice(["Vermont", "Texas", "Ohio", "California"]),
             "Shares Owned": str(random.randint(1, 99999)),
             "Acquisition Date": f"20{random.randint(15,25):02d}-01-01"} for _ in range(1000)]
    t = time.perf_counter()
    apply_gate(rows, k_threshold=5)
    dt = time.perf_counter() - t
    perf_check.check("gate_rows_per_sec", 1000 / dt, higher_is_better=True)


# ---- fuzz gate ------------------------------------------------------------

def test_fuzz_detects_exception(run_fuzz):
    def bad(_):
        raise ValueError("boom")
    assert len(run_fuzz(bad, ["x", "y"])) == 2  # gate CAN fail


def test_fuzz_clean_target(run_fuzz):
    assert run_fuzz(lambda _: True, ["x"]) == []


def test_corpus_present(corpus_files):
    assert len(corpus_files) >= 3  # seed malformed inputs exist for Phase 1
