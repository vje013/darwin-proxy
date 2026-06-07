"""Shared test harness for v1 and v2.

Provides model-free fixtures (blank spaCy engine, hash embedder) and the three
quality gates as fixtures whose pure helpers are independently testable:
  golden      stable golden-file comparison
  run_fuzz    run a target over a corpus, report uncaught exceptions
  perf_check  compare a measurement to a committed baseline, fail on regression
"""
import json
import os
import pathlib
import warnings

import pytest

warnings.filterwarnings("ignore")

ROOT = pathlib.Path(__file__).parent
GOLDENS = ROOT / "goldens"
CORPUS = ROOT / "corpus"
BASELINES = ROOT.parent / "benchmarks" / "baselines.json"


# ---- model-free engines ---------------------------------------------------

def _blank_engine():
    import spacy
    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    class Blank(SpacyNlpEngine):
        def __init__(self):
            super().__init__(models=[{"lang_code": "en", "model_name": "en_core_web_lg"}])
            self.nlp = {"en": spacy.blank("en")}
    return Blank()


@pytest.fixture(scope="session")
def hash_embedder():
    import hashlib
    from chromadb.api.types import EmbeddingFunction, Documents, Embeddings

    class HashEmbedder(EmbeddingFunction[Documents]):
        def __init__(self):
            pass

        def __call__(self, input: Documents) -> Embeddings:
            out = []
            for t in input:
                h = hashlib.sha256(t.lower().encode()).digest()
                out.append([((h[i % len(h)] / 255.0) * 2 - 1) for i in range(48)])
            return out

        @staticmethod
        def name() -> str:
            return "hash-test"

        def get_config(self):
            return {}

        @classmethod
        def build_from_config(cls, config):
            return cls()

    return HashEmbedder()


# ---- golden gate ----------------------------------------------------------

class _Golden:
    def __init__(self, update):
        self.update = update

    @staticmethod
    def compare(expected, actual):
        return expected == actual

    def check(self, name, value):
        GOLDENS.mkdir(exist_ok=True)
        path = GOLDENS / f"{name}.json"
        normalized = json.loads(json.dumps(value, default=str, sort_keys=True))
        if self.update or not path.exists():
            path.write_text(json.dumps(normalized, indent=2, sort_keys=True))
            return
        expected = json.loads(path.read_text())
        assert self.compare(expected, normalized), f"golden mismatch for {name}"


@pytest.fixture
def golden():
    return _Golden(update=os.environ.get("PROXY_UPDATE_GOLDENS") == "1")


# ---- fuzz gate ------------------------------------------------------------

def _run_fuzz(target, files):
    """Run target over each file; collect uncaught exceptions as failures."""
    failures = []
    for f in files:
        try:
            target(f)
        except Exception as e:  # noqa: BLE001 - the point is to catch anything
            failures.append((str(f), repr(e)))
    return failures


@pytest.fixture
def run_fuzz():
    return _run_fuzz


@pytest.fixture
def corpus_files():
    return sorted(CORPUS.glob("*"))


# ---- perf gate ------------------------------------------------------------

class _Perf:
    def __init__(self, update, band=0.3):
        self.update = update
        self.band = band

    @staticmethod
    def evaluate(baseline, measured, higher_is_better=True, band=0.3):
        if higher_is_better:
            return measured >= baseline * (1 - band)
        return measured <= baseline * (1 + band)

    def check(self, name, measured, higher_is_better=True):
        BASELINES.parent.mkdir(exist_ok=True)
        data = json.loads(BASELINES.read_text()) if BASELINES.exists() else {}
        if self.update or name not in data:
            data[name] = measured
            BASELINES.write_text(json.dumps(data, indent=2, sort_keys=True))
            return
        ok = self.evaluate(data[name], measured, higher_is_better, self.band)
        assert ok, f"perf regression {name}: {measured} vs baseline {data[name]} (band {self.band})"


@pytest.fixture
def perf_check():
    return _Perf(update=os.environ.get("PROXY_UPDATE_BASELINES") == "1")
