"""Phase 1 exit gate: re-identification gate enforces k-anonymity."""

from proxy.gate import apply_gate


def _row(state, cls, shares, date):
    return {"State": state, "Share Class": cls, "Shares Owned": shares, "Acquisition Date": date}


def test_unique_rows_trip_then_pass():
    # Every row is unique by exact shares + date -> k=1, must trip the gate.
    rows = [
        _row("Vermont", "Common", "100", "2025-01-01"),
        _row("Maine", "Common", "200", "2025-01-02"),
        _row("New York", "Common", "300", "2025-01-03"),
        _row("California", "Common", "400", "2025-01-04"),
        _row("Oregon", "Common", "500", "2025-01-05"),
        _row("Washington", "Common", "600", "2025-01-06"),
    ]
    gated, result = apply_gate(rows, k_threshold=3)
    assert result["passed"] is True
    assert result["k"] >= 3
    assert result["generalized"]  # something had to be widened


def test_already_anonymous_passes_untouched():
    # Two equivalence classes of 3, already 3-anonymous on identity fields.
    rows = [_row("Vermont", "Common", "100", "2025-01-01") for _ in range(3)]
    rows += [_row("Texas", "Common", "100", "2025-01-01") for _ in range(3)]
    gated, result = apply_gate(rows, k_threshold=3)
    assert result["passed"] is True
    assert result["k"] >= 3
    assert result["generalized"] == {}  # no generalization needed


def test_cannot_pass_when_dataset_too_small():
    rows = [_row("Vermont", "Common", "100", "2025-01-01")]
    gated, result = apply_gate(rows, k_threshold=5)
    assert result["passed"] is False
    assert result["k"] == 1


def test_result_shape():
    rows = [_row("Vermont", "Common", "100", "2025-01-01")]
    _, result = apply_gate(rows, k_threshold=2)
    for key in ("k", "threshold", "passed", "quasi_identifiers", "generalized"):
        assert key in result


def test_pipeline_sets_gate_result(tmp_path):
    import csv as _csv
    from proxy import Proxy
    src = tmp_path / "in.csv"
    with open(src, "w", newline="") as f:
        w = _csv.writer(f)
        w.writerow(["Stockholder ID", "First Name", "Last Name", "State", "Share Class", "Shares Owned", "Acquisition Date"])
        for i in range(8):
            w.writerow([f"SH-{i}", "John", "Reed", "Vermont", "Common", str(1000 + i), "2025-01-01"])
    out = tmp_path / "out.csv"
    manifest, _, _ = Proxy().abstract_csv(str(src), str(out), k_threshold=3)
    assert manifest.gate_result is not None
    assert "passed" in manifest.gate_result
