"""Semantic classification.

Two kinds of class:
  - cheap, exact heuristics for fields with a closed value space: gender for
    first names, US region for states. No model needed; these are correct and fast.
  - embedding-neighborhood classification for open-ended fields (org / business
    name) via Chroma: a seed corpus of labeled exemplars per sector is embedded,
    and a value is classified by its nearest neighbor. This drives same-sector
    substitution so portfolio composition survives abstraction.

The Chroma embedder is injectable. Production uses Chroma's default model; tests
inject a deterministic hash embedder so the mechanism runs with no model download.
The whole thing degrades gracefully: if the backend is unavailable, org values
fall back to a generic company substitution and lose only the sector attribute.
"""
import gender_guesser.detector as gender
from proxy.schemas import SemanticClass

_detector = gender.Detector()

REGIONS = {
    "Northeast": ["Connecticut", "Maine", "Massachusetts", "New Hampshire", "Rhode Island",
                  "Vermont", "New Jersey", "New York", "Pennsylvania"],
    "Southeast": ["Alabama", "Arkansas", "Florida", "Georgia", "Kentucky", "Louisiana",
                  "Mississippi", "North Carolina", "South Carolina", "Tennessee", "Virginia",
                  "West Virginia", "Maryland", "Delaware"],
    "Midwest": ["Illinois", "Indiana", "Iowa", "Kansas", "Michigan", "Minnesota", "Missouri",
                "Nebraska", "North Dakota", "Ohio", "South Dakota", "Wisconsin"],
    "Southwest": ["Arizona", "New Mexico", "Oklahoma", "Texas"],
    "West": ["Alaska", "California", "Colorado", "Hawaii", "Idaho", "Montana", "Nevada",
             "Oregon", "Utah", "Washington", "Wyoming"],
}
STATE_TO_REGION = {s: r for r, states in REGIONS.items() for s in states}

# Seed corpus: labeled exemplars per sector. Doubles as the substitution pool, so
# an org is replaced by a different same-sector entity. Expand per deployment.
FINANCE_CORPUS = {
    "Financials": ["Goldman Sachs", "Morgan Stanley", "JPMorgan Chase", "Citigroup",
                   "Bank of America", "Wells Fargo", "BlackRock", "Charles Schwab",
                   "American Express", "Capital One"],
    "Technology": ["Apple", "Microsoft", "Nvidia", "Alphabet", "Meta Platforms",
                   "Oracle", "Salesforce", "Adobe", "Intel", "Cisco Systems"],
    "Healthcare": ["Pfizer", "Johnson & Johnson", "Merck", "AbbVie", "Eli Lilly",
                   "UnitedHealth Group", "Amgen", "Gilead Sciences", "Bristol Myers Squibb", "CVS Health"],
    "Energy": ["ExxonMobil", "Chevron", "ConocoPhillips", "Schlumberger", "Marathon Petroleum",
               "Phillips 66", "Valero Energy", "Occidental Petroleum", "Kinder Morgan", "Halliburton"],
    "Consumer": ["Procter & Gamble", "Coca-Cola", "PepsiCo", "Walmart", "Costco",
                 "Nike", "McDonald's", "Starbucks", "Target", "Mondelez"],
    "Industrials": ["Boeing", "Caterpillar", "General Electric", "Honeywell", "3M",
                    "Lockheed Martin", "Union Pacific", "Deere & Company", "Raytheon", "Emerson Electric"],
    "RealEstate": ["Prologis", "American Tower", "Simon Property Group", "Realty Income",
                   "Public Storage", "Equinix", "Welltower", "Digital Realty", "AvalonBay", "Boston Properties"],
}
SECTOR_COMPANIES = FINANCE_CORPUS


def default_embedder():
    from chromadb.utils import embedding_functions
    return embedding_functions.DefaultEmbeddingFunction()


class ChromaBackend:
    """Embedding-neighborhood org classification, lazy so no model loads until used."""

    def __init__(self, embedding_function=None, corpus=None):
        self._ef = embedding_function
        self._corpus = corpus or FINANCE_CORPUS
        self._col = None

    def _collection(self):
        if self._col is None:
            import chromadb
            ef = self._ef or default_embedder()
            client = chromadb.Client()
            col = client.create_collection(name="orgs", embedding_function=ef)
            ids, docs, metas = [], [], []
            for sector, names in self._corpus.items():
                for n in names:
                    ids.append(n)
                    docs.append(n)
                    metas.append({"sector": sector})
            col.add(ids=ids, documents=docs, metadatas=metas)
            self._col = col
        return self._col

    def classify_org(self, value):
        try:
            r = self._collection().query(query_texts=[value], n_results=1)
            sector = r["metadatas"][0][0]["sector"]
            dist = float(r["distances"][0][0])
            return sector, dist
        except Exception:
            return "unknown", 1.0


class SemanticClassifier:
    def __init__(self, org_backend=None):
        self._org_backend = org_backend
        self._lazy_default = org_backend is None

    def _org(self):
        if self._org_backend is None:
            self._org_backend = ChromaBackend()
        return self._org_backend

    def classify(self, field, entity_type, value):
        attrs, radius = {}, 1.0
        if entity_type == "PERSON" and field == "First Name":
            attrs["gender"] = _detector.get_gender(value)
        if entity_type == "LOCATION" and field == "State":
            attrs["region"] = STATE_TO_REGION.get(value, "unknown")
        if entity_type == "ORG":
            sector, dist = self._org().classify_org(value)
            attrs["sector"] = sector
            radius = dist
        return SemanticClass(field=field, entity_type=entity_type, attributes=attrs, radius=radius)
