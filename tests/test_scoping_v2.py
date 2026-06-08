"""P2: entity scoping and the no-NER fast path. A pattern-only Detector needs no
model and runs at pattern speed; the manifest records detection_mode so a no-NER
run cannot be mistaken for a full scan."""
import pandas as pd

from proxy.cert import generate_key
from proxy.detection import Detector
from proxy.ingest import Table
from proxy.orchestrator import Proxy


def _t(**cols):
    return Table(pd.DataFrame(cols))


def test_no_ner_detector_needs_no_model_and_finds_patterns():
    # ner=False injects a blank engine: no model load, pattern entities still detected
    d = Detector(ner=False)
    m = d.analyze_table(_t(email=["a@x.com", "b@y.com"], ssn=["123-45-6789", "987-65-4320"],
                           name=["John Smith", "Jane Doe"]))
    assert m["email"] == "EMAIL_ADDRESS" and m["ssn"] == "US_SSN"
    assert "name" not in m                       # PERSON needs NER, which is off


def test_entities_scoping_filters_mapping():
    d = Detector(ner=False)
    t = _t(email=["a@x.com", "b@y.com"], ssn=["123-45-6789", "987-65-4320"])
    scoped = d.analyze_table(t, entities=["EMAIL_ADDRESS"])
    assert scoped == {"email": "EMAIL_ADDRESS"}   # ssn excluded by scope


def test_manifest_records_pattern_only_mode():
    px = Proxy(ner=False, signing_key=generate_key(), k_threshold=2)
    _out, manifest = px.abstract_table(_t(email=["a@x.com", "b@y.com"]))
    assert manifest.detection_mode == "pattern-only"   # verifier sees names were not scanned


def test_manifest_records_full_mode_by_default():
    import spacy
    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    class _Blank(SpacyNlpEngine):
        def __init__(self):
            super().__init__(models=[{"lang_code": "en", "model_name": "en_core_web_lg"}])
            self.nlp = {"en": spacy.blank("en")}
    # ner defaults True; an injected engine is still "full" mode (names would be scanned with a real model)
    px = Proxy(nlp_engine=_Blank(), signing_key=generate_key(), k_threshold=2)
    _out, manifest = px.abstract_table(_t(email=["a@x.com", "b@y.com"]))
    assert manifest.detection_mode == "full"
