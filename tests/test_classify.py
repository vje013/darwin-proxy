"""Embedding-neighborhood sector classification, model-free via a deterministic
hash embedder. Tests the mechanism: corpus members classify to their own sector,
and gender/region heuristics resolve. Semantic generalization to unseen orgs needs
the real embedder, validated on host. (Sector-preserving substitution was a v1
path retired at the v2 cutover; classify stays as optional enrichment plus the
region tables the gate uses.)
"""
import hashlib

import pytest
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings

from proxy.classify import ChromaBackend, SemanticClassifier

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
    assert classifier.classify("Business Name", "ORG", "Goldman Sachs").attributes["sector"] == "Financials"
    assert classifier.classify("Business Name", "ORG", "Nvidia").attributes["sector"] == "Technology"


def test_gender_and_region_still_work(classifier):
    g = classifier.classify("First Name", "PERSON", "John")
    assert g.attributes["gender"] in ("male", "mostly_male")
    r = classifier.classify("State", "LOCATION", "Connecticut")
    assert r.attributes["region"] == "Northeast"
