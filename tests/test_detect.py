"""Phase 2 exit: inline finance entities caught in free-text without a column rule."""

import csv as _csv

from proxy import Proxy
from proxy.detect import FinanceScanner, redact_inline
from proxy.recognizers import aba_valid, cusip_valid, isin_valid


def test_checksums():
    assert aba_valid("021000021") and not aba_valid("021000022")
    assert cusip_valid("037833100") and not cusip_valid("037833101")
    assert isin_valid("US0378331005") and not isin_valid("US0378331006")


def test_scanner_finds_finance_entities():
    sc = FinanceScanner()
    spans = sc.scan("SSN 123-45-6789, routing 021000021, CUSIP 037833100, ISIN US0378331005")
    found = {s.entity_type for s in spans}
    assert {"US_SSN", "US_ABA_ROUTING", "CUSIP", "ISIN"} <= found


def test_bad_checksum_not_flagged():
    sc = FinanceScanner()
    # 021000022 fails the ABA checksum -> not a routing number
    spans = sc.scan("routing 021000022")
    assert all(s.entity_type != "US_ABA_ROUTING" for s in spans)


def test_account_requires_context():
    sc = FinanceScanner()
    assert any(s.entity_type == "FIN_ACCOUNT" for s in sc.scan("account 0123456789"))
    assert not any(s.entity_type == "FIN_ACCOUNT" for s in sc.scan("order 0123456789 shipped"))


def test_redact_inline_replaces_spans():
    sc = FinanceScanner()
    text = "wire to routing 021000021 today"
    out = redact_inline(text, sc.scan(text))
    assert "021000021" not in out and "[US_ABA_ROUTING]" in out


def test_pipeline_catches_inline_without_column_rule(tmp_path):
    # 'Notes' has no policy rule -> SIGNAL -> must still be scanned and redacted.
    src = tmp_path / "in.csv"
    with open(src, "w", newline="") as f:
        w = _csv.writer(f)
        w.writerow(["Stockholder ID", "First Name", "Notes", "Share Class", "Shares Owned", "Acquisition Date"])
        for i in range(6):
            w.writerow([f"SH-{i}", "John", f"SSN 123-45-678{i} routing 021000021", "Common", "1000", "2025-01-01"])
    out = tmp_path / "out.csv"
    manifest, _, out_rows = Proxy().abstract_csv(str(src), str(out), k_threshold=3)
    assert manifest.inline_redactions
    assert manifest.inline_redactions.get("US_ABA_ROUTING", 0) >= 6
    assert all("021000021" not in r["Notes"] for r in out_rows)
