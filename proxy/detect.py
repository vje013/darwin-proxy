"""Field detection.

Two layers:
  1. Column policy (override): maps known columns to (entity_type, mode).
     Anything unlisted is SIGNAL (kept), then scanned inline by layer 2.
  2. Inline scan (FinanceScanner): a Presidio AnalyzerEngine with a spaCy NLP
     engine, the predefined recognizers, and the custom finance recognizers
     registered. Catches inline finance identifiers (SSN, routing, CUSIP, ISIN,
     EIN, account) and NER entities (PERSON, ORG, LOCATION) in free-text values,
     with no column rule required.

The policy wins where it is set; the scanner only touches what the policy leaves
as SIGNAL, so pinning a column always overrides inline detection.

Model: set PROXY_SPACY_MODEL (default en_core_web_lg). Install once on the host:
    pip install presidio-analyzer
    python -m spacy download en_core_web_lg     # or en_core_web_sm (lighter)
"""
import os

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from proxy.recognizers import finance_recognizers, CONTEXT_REQUIRED, FINANCE_ENTITIES
from proxy.schemas import Span

DEFAULT_MODEL = os.environ.get("PROXY_SPACY_MODEL", "en_core_web_lg")
NER_ENTITIES = ["PERSON", "ORG", "LOCATION"]


class Mode:
    SEMANTIC = "semantic"   # classify + substitute from a semantic neighborhood
    FORMAT = "format"       # structurally valid fake, no semantic hop
    DERIVED = "derived"     # derived from other replacements (e.g. email)
    SIGNAL = "signal"       # keep as-is (analytical signal, not identity)


DEFAULT_POLICY = {
    "First Name": ("PERSON", Mode.SEMANTIC),
    "Last Name": ("PERSON", Mode.SEMANTIC),
    "Email": ("EMAIL", Mode.DERIVED),
    "Business Name": ("ORG", Mode.SEMANTIC),
    "Phone Number": ("PHONE", Mode.FORMAT),
    "City": ("LOCATION", Mode.SEMANTIC),
    "State": ("LOCATION", Mode.SEMANTIC),
    "Country": ("LOCATION", Mode.SEMANTIC),
}


def classify_fields(record, policy=None):
    """Map each field to (entity_type, mode). Unlisted fields are SIGNAL."""
    policy = policy or DEFAULT_POLICY
    return {f: policy.get(f, (None, Mode.SIGNAL)) for f in record}


def build_analyzer(model=None, nlp_engine=None):
    """AnalyzerEngine with predefined + finance recognizers. Accepts an injected
    nlp_engine for testing; otherwise loads the configured spaCy model."""
    if nlp_engine is None:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model or DEFAULT_MODEL}],
        })
        nlp_engine = provider.create_engine()
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine)
    for rec in finance_recognizers():
        registry.add_recognizer(rec)
    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry, supported_languages=["en"])


class FinanceScanner:
    """Inline entity detection over free-text values, backed by Presidio."""

    SCORE_THRESHOLD = 0.4
    CONTEXT_WINDOW = 40
    FREETEXT_MIN_TOKENS = 3

    def __init__(self, model=None, nlp_engine=None, entities=None):
        self._model = model
        self._nlp_engine = nlp_engine
        self._analyzer = None
        self._entities_override = entities
        self._context = {r.supported_entities[0]: [c.lower() for c in (r.context or [])]
                         for r in finance_recognizers()}

    @property
    def analyzer(self):
        # Built on first scan so constructing a Proxy never loads the spaCy model
        # unless a free-text value is actually scanned.
        if self._analyzer is None:
            self._analyzer = build_analyzer(model=self._model, nlp_engine=self._nlp_engine)
        return self._analyzer

    def _entities_for(self, text):
        if self._entities_override is not None:
            return self._entities_override
        ents = list(FINANCE_ENTITIES)
        # NER (names/orgs/places) only on prose, not single structured cells.
        if len(text.split()) >= self.FREETEXT_MIN_TOKENS:
            ents += NER_ENTITIES
        return ents

    def scan(self, text):
        if not text or not isinstance(text, str):
            return []
        low = text.lower()
        results = self.analyzer.analyze(text=text, entities=self._entities_for(text),
                                        language="en", score_threshold=self.SCORE_THRESHOLD)
        spans = []
        for r in results:
            ent = r.entity_type
            if ent in CONTEXT_REQUIRED and not self._has_context(low, r.start, r.end, ent):
                continue
            spans.append(Span(text=text[r.start:r.end], start=r.start, end=r.end,
                              entity_type=ent, score=float(r.score)))
        return self._merge(spans, low)

    def _has_context(self, low_text, start, end, ent):
        return self._nearest_ctx(low_text, start, end, ent) is not None

    def _nearest_ctx(self, low_text, start, end, ent):
        """Char distance from the span to the closest context word in window, or None."""
        words = self._context.get(ent) or []
        lo = max(0, start - self.CONTEXT_WINDOW)
        hi = min(len(low_text), end + self.CONTEXT_WINDOW)
        window = low_text[lo:hi]
        best = None
        for w in words:
            i = window.find(w)
            while i >= 0:
                ws, we = lo + i, lo + i + len(w)
                d = start - we if we <= start else (ws - end if ws >= end else 0)
                best = d if best is None else min(best, d)
                i = window.find(w, i + 1)
        return best

    _PRIORITY = {"US_SSN": 0, "US_ABA_ROUTING": 1, "FIN_ACCOUNT": 2, "ISIN": 3, "CUSIP": 4}

    def _merge(self, spans, low_text):
        # Cluster overlapping spans; within each cluster keep one winner.
        spans = sorted(spans, key=lambda x: x.start)
        clusters, cur, end = [], [], -1
        for s in spans:
            if s.start >= end:
                if cur:
                    clusters.append(cur)
                cur, end = [s], s.end
            else:
                cur.append(s)
                end = max(end, s.end)
        if cur:
            clusters.append(cur)

        def key(s):
            d = self._nearest_ctx(low_text, s.start, s.end, s.entity_type)
            # context present beats none; then nearest context; then score; then priority
            return (d is None, d if d is not None else 1e9, -s.score,
                    self._PRIORITY.get(s.entity_type, 99))

        return [sorted(cl, key=key)[0] for cl in clusters]


def redact_inline(text, spans):
    """Replace detected spans with a typed placeholder, right to left."""
    out = text
    for s in sorted(spans, key=lambda x: x.start, reverse=True):
        out = out[:s.start] + f"[{s.entity_type}]" + out[s.end:]
    return out
