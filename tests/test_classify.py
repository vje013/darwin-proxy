"""Phase 5: embedding-neighborhood sector classification + sector-preserving sub.

Uses a deterministic hash embedder (no model download). It tests the mechanism:
corpus members classify to their own sector, and ORG substitution stays in-sector.
Semantic generalization to unseen orgs needs the real embedder, validated on host.
"""
import hashlib

import pytest
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings

from proxy.classify import ChromaBackend, SemanticClassifier, FINANCE_CORPUS, SECTOR_COMPANIES
from proxy.substitute import Substitutor

_DIM = 48


class HashEmbedder(EmbeddingFunction[Documents]):
    def __init__(self):
        pass

    def __call__(self, input: Documents) -> Embeddings:
        out = []
        for t in input:
            h = hashlib.sha256(t.lower().encode()).digest()
            out.append([((h[i % len(h)] / 255.0) * 2 - 1) for i in range(_DIM)])
        return out

    @staticmethod
    def name() -> str:
        return "hash-test"

    def get_config(self):
        return {}

    @classmethod
    def build_from_config(cls, config):
        return cls()


@pytest.fixture(scope="module")
def classifier():
    return SemanticClassifier(org_backend=ChromaBackend(embedding_function=HashEmbedder()))


def test_corpus_member_classifies_to_its_sector(classifier):
    sc = classifier.classify("Business Name", "ORG", "Goldman Sachs")
    assert sc.attributes["sector"] == "Financials"
    sc2 = classifier.classify("Business Name", "ORG", "Nvidia")
    assert sc2.attributes["sector"] == "Technology"


def test_org_substitution_stays_in_sector(classifier):
    sc = classifier.classify("Business Name", "ORG", "Goldman Sachs")
    repl = Substitutor(key="k").substitute("Business Name", "ORG", "Goldman Sachs", sc)
    assert repl in SECTOR_COMPANIES["Financials"] and repl != "Goldman Sachs"


def test_unknown_sector_falls_back(classifier):
    # Backend returns a nearest sector; substitution must still produce a value.
    from proxy.schemas import SemanticClass
    sc = SemanticClass(field="Business Name", entity_type="ORG", attributes={"sector": "unknown"})
    repl = Substitutor(key="k").substitute("Business Name", "ORG", "Some LLC", sc)
    assert isinstance(repl, str) and repl != "Some LLC"


def test_gender_and_region_still_work(classifier):
    g = classifier.classify("First Name", "PERSON", "John")
    assert g.attributes["gender"] in ("male", "mostly_male")
    r = classifier.classify("State", "LOCATION", "Connecticut")
    assert r.attributes["region"] == "Northeast"
