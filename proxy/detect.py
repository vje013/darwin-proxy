"""Field detection.

Two layers:
  1. Column policy (override): maps known columns to (entity_type, mode).
     Anything unlisted is SIGNAL (kept), then scanned inline by layer 2.
  2. Inline scan (FinanceScanner): Presidio pattern recognizers + finance
     recognizers find entity spans inside free-text values. Catches an SSN or
     routing number embedded in a field with no column rule.

The policy wins where it is set; the scanner only touches what the policy leaves
as SIGNAL, so pinning a column always overrides inline detection.
"""
from proxy.recognizers import all_recognizers, CONTEXT_REQUIRED
from proxy.schemas import Span


class Mode:
    SEMANTIC = "semantic"   # classify + substitute from a semantic neighborhood
    FORMAT = "format"       # structurally valid fake, no semantic hop
    DERIVED = "derived"     # derived from other replacements (e.g. email)
    SIGNAL = "signal"       # keep as-is (analytical signal, not identity)


# (entity_type, mode) per field. Anything unlisted is treated as SIGNAL.
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


class FinanceScanner:
    """Inline entity detection over free-text values. Standalone (no spaCy)."""

    CONTEXT_WINDOW = 40

    def __init__(self):
        self._recognizers = all_recognizers()
        self._entities = [r.supported_entities[0] for r in self._recognizers]
        self._context = {r.supported_entities[0]: [c.lower() for c in (r.context or [])]
                         for r in self._recognizers}

    def scan(self, text):
        if not text or not isinstance(text, str):
            return []
        low = text.lower()
        raw = []
        for rec in self._recognizers:
            ent = rec.supported_entities[0]
            for res in rec.analyze(text, entities=[ent], nlp_artifacts=None):
                if ent in CONTEXT_REQUIRED and not self._has_context(low, res.start, res.end, ent):
                    continue
                raw.append(Span(text=text[res.start:res.end], start=res.start,
                                end=res.end, entity_type=ent, score=float(res.score)))
        return self._merge(raw)

    def _has_context(self, low_text, start, end, ent):
        lo = max(0, start - self.CONTEXT_WINDOW)
        hi = min(len(low_text), end + self.CONTEXT_WINDOW)
        window = low_text[lo:hi]
        return any(w in window for w in self._context.get(ent, []))

    @staticmethod
    def _merge(spans):
        # Keep highest-score, non-overlapping spans.
        chosen = []
        for s in sorted(spans, key=lambda x: (x.start, -x.score)):
            if all(s.start >= c.end or s.end <= c.start for c in chosen):
                chosen.append(s)
        return sorted(chosen, key=lambda x: x.start)


def redact_inline(text, spans):
    """Replace detected spans with a typed placeholder, right to left."""
    out = text
    for s in sorted(spans, key=lambda x: x.start, reverse=True):
        out = out[:s.start] + f"[{s.entity_type}]" + out[s.end:]
    return out
