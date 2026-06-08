"""Analyzer construction. Predefined recognizers (credit card, IBAN, IP, SSN,
phone, passport, and the rest) plus our checksum finance recognizers, over a
spaCy NLP engine. The engine is injectable so tests run model-free, and supports
multiple languages for locale coverage.
"""
import os

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from proxy.recognizers import finance_recognizers

DEFAULT_MODEL = os.environ.get("PROXY_SPACY_MODEL", "en_core_web_lg")


def blank_nlp_engine(language="en"):
    """A spaCy engine with no NER model loaded. Pattern recognizers still fire;
    PERSON/ORG/LOCATION do not. This is the no-NER fast path: no model download,
    no NER cost, pattern speed for structured data that does not need name lookup."""
    import spacy
    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    class _Blank(SpacyNlpEngine):
        def __init__(self):
            super().__init__(models=[{"lang_code": language, "model_name": DEFAULT_MODEL}])
            self.nlp = {language: spacy.blank(language)}
    return _Blank()


def build_analyzer(nlp_engine=None, model=None, languages=("en",), finance=True):
    languages = list(languages)
    if nlp_engine is None:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": lang, "model_name": model or DEFAULT_MODEL} for lang in languages],
        })
        nlp_engine = provider.create_engine()
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(languages=languages, nlp_engine=nlp_engine)
    if finance:
        for rec in finance_recognizers():
            registry.add_recognizer(rec)
    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry, supported_languages=languages)
