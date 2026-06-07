"""Shared test fixtures. A blank spaCy pipeline lets the Presidio engine run in
tests without downloading a model: it exercises the finance recognizers, context
gating, merge, and redaction. spaCy NER (PERSON/ORG/LOCATION) needs a real model
and is validated on the host, not here.
"""
import warnings
import pytest
import spacy
from presidio_analyzer.nlp_engine import SpacyNlpEngine

from proxy.detect import FinanceScanner

warnings.filterwarnings("ignore")


class _BlankSpacy(SpacyNlpEngine):
    def __init__(self):
        super().__init__(models=[{"lang_code": "en", "model_name": "en_core_web_lg"}])
        self.nlp = {"en": spacy.blank("en")}


@pytest.fixture(scope="session")
def scanner():
    return FinanceScanner(nlp_engine=_BlankSpacy())
