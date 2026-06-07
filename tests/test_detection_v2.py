"""Phase 2: content-based detection. Columns are classified by their values, not
their header names. Model-free via the blank engine, so the proofs use pattern
entities (email, credit card, SSN, routing, CUSIP). NER entities (PERSON/ORG)
need the real model and are validated on the host."""
import warnings

import pandas as pd
import pytest

from proxy.detection import Detector
from proxy.ingest import read_records, Table

warnings.filterwarnings("ignore")


@pytest.fixture(scope="module")
def detector():
    return _blank_detector()


def _blank_detector():
    import spacy
    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    class Blank(SpacyNlpEngine):
        def __init__(self):
            super().__init__(models=[{"lang_code": "en", "model_name": "en_core_web_lg"}])
            self.nlp = {"en": spacy.blank("en")}
    return Detector(nlp_engine=Blank(), score_threshold=0.5)


def _df(**cols):
    return Table(pd.DataFrame(cols))


def test_content_based_detection_ignores_headers(detector):
    t = _df(col_x=["a@x.com", "b@y.com", "c@z.com"],
            weird2=["4111111111111111", "4012888888881881", "4222222222222"],
            zzz=["123-45-6789", "987-65-4320", "078-05-1120"])
    m = detector.analyze_table(t)
    assert m["col_x"] == "EMAIL_ADDRESS"
    assert m["weird2"] == "CREDIT_CARD"
    assert m["zzz"] == "US_SSN"


def test_header_name_invariance(detector):
    vals = {"emails": ["a@x.com", "b@y.com"], "cards": ["4111111111111111", "4012888888881881"]}
    m1 = detector.analyze_table(_df(**vals))
    renamed = {"qqq": vals["emails"], "zzz": vals["cards"]}
    m2 = detector.analyze_table(_df(**renamed))
    assert list(m1.values()) == list(m2.values())  # same entities, header names irrelevant


def test_signal_column_not_flagged(detector):
    t = _df(shares=["16249", "39024", "24104"], note=["aa", "bb", "cc"])
    m = detector.analyze_table(t)
    assert "shares" not in m and "note" not in m  # plain values stay signal


def test_finance_recognizers_in_columns(detector):
    t = _df(routing=["021000021", "011401533", "091000019"],
            cusip=["037833100", "459200101", "594918104"])
    m = detector.analyze_table(t)
    assert m["routing"] == "US_ABA_ROUTING"
    assert m["cusip"] == "CUSIP"


def test_override_pins_and_suppresses(detector):
    t = _df(col_x=["a@x.com", "b@y.com"], keepme=["x", "y"])
    m = detector.analyze_table(t, override={"keepme": "PERSON", "col_x": None})
    assert m["keepme"] == "PERSON"   # pinned
    assert "col_x" not in m          # suppressed (force keep)


def test_scan_cell_threshold_gates():
    # score_threshold gates the cell/narrative path (analyzer.analyze honors it).
    # analyze_table's column mapping is not score-gated; its controls are
    # selection_strategy and the override policy.
    text = "reference 0123456789 here"  # bare 10-digit, no account context -> FIN_ACCOUNT 0.5
    loose = _blank_detector(); loose.score_threshold = 0.4
    assert any(s[0] == "FIN_ACCOUNT" for s in loose.scan_cell(text))
    strict = _blank_detector(); strict.score_threshold = 0.6
    assert not any(s[0] == "FIN_ACCOUNT" for s in strict.scan_cell(text))


def test_scan_cell_narrative(detector):
    spans = detector.scan_cell("client SSN 123-45-6789 wire routing 021000021")
    kinds = {s[0] for s in spans}
    assert "US_SSN" in kinds and "US_ABA_ROUTING" in kinds


def test_language_param_plumbs(detector):
    t = _df(card=["4111111111111111", "4012888888881881"])
    m = detector.analyze_table(t, language="en")  # pattern entity, language-agnostic
    assert m["card"] == "CREDIT_CARD"


def test_detection_golden(detector, golden):
    t = _df(email=["a@x.com", "b@y.com"], ssn=["123-45-6789", "987-65-4320"],
            routing=["021000021", "011401533"])
    golden.check("phase2_entity_mapping", detector.analyze_table(t))


@pytest.mark.perf
def test_detection_perf(detector, perf_check):
    import time
    n = 500
    t = _df(email=[f"u{i}@x.com" for i in range(n)],
            ssn=["123-45-6789"] * n, routing=["021000021"] * n)
    detector.analyze_table(_df(email=["warm@up.com"]))  # warm: move lazy analyzer build out of the timing
    t0 = time.perf_counter()
    detector.analyze_table(t)
    dt = time.perf_counter() - t0
    perf_check.check("detect_cols_per_sec", 3 / dt, higher_is_better=True)
