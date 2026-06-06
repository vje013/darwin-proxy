"""Field detection. v0 is policy-driven for structured records.
Presidio free-text detection slots in here later behind the same interface.
"""


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
