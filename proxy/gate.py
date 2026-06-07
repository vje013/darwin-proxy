"""Re-identification gate. k-anonymity over quasi-identifier combinations,
applied to the abstracted dataset as a reduce step after substitution.

Strips identity at substitution; this kills re-identifiability by linkage.
A record with a fake name is still a fingerprint if its remaining fields
(region, holdings, acquisition date) are unique. The gate generalizes those
quasi-identifiers until every combination is shared by at least k records.

Algorithm: greedy full-domain generalization to reach k, then a rollback pass
that de-generalizes any field that isn't needed, to recover utility. This is a
heuristic; optimal lattice search / Mondrian is a later refinement.
"""
from collections import Counter

from proxy.classify import STATE_TO_REGION


def _identity(v):
    return "" if v is None else str(v)


def _suppress(v):
    return "*"


def _region(v):
    return STATE_TO_REGION.get(str(v), "*")


def _band(width):
    def f(v):
        try:
            n = int(float(v))
        except (ValueError, TypeError):
            return _suppress(v)
        lo = (n // width) * width
        return f"{lo}-{lo + width - 1}"
    return f


def _prefix(length):
    def f(v):
        s = "" if v is None else str(v)
        return s[:length] if len(s) >= length else _suppress(v)
    return f


# Per-field generalization ladders. Level 0 = most specific, last = suppressed.
DEFAULT_QI = {
    "State": [_identity, _region, _suppress],
    "Share Class": [_identity, _suppress],
    "Shares Owned": [_identity, _band(10000), _band(50000), _suppress],
    "Acquisition Date": [_identity, _prefix(7), _prefix(4), _suppress],
}


def _qi_tuple(row, fields, qi, levels):
    return tuple(qi[f][levels[f]](row.get(f)) for f in fields)


def _min_k(rows, fields, qi, levels):
    if not rows:
        return 0
    counts = Counter(_qi_tuple(r, fields, qi, levels) for r in rows)
    return min(counts.values())


def _classes(rows, fields, qi, levels):
    return len({_qi_tuple(r, fields, qi, levels) for r in rows})


def apply_gate(rows, qi_config=None, k_threshold=5, max_rounds=64):
    qi = qi_config or DEFAULT_QI
    fields = [f for f in qi if rows and f in rows[0]]
    levels = {f: 0 for f in fields}

    k = _min_k(rows, fields, qi, levels)

    # Greedy: widen toward k. Pick the step that most raises k, then most merges.
    rounds = 0
    while k < k_threshold and rounds < max_rounds:
        candidates = [f for f in fields if levels[f] < len(qi[f]) - 1]
        if not candidates:
            break
        best_score, best_field = None, None
        for f in candidates:
            levels[f] += 1
            score = (_min_k(rows, fields, qi, levels), -_classes(rows, fields, qi, levels))
            levels[f] -= 1
            if best_score is None or score > best_score:
                best_score, best_field = score, f
        levels[best_field] += 1
        k = _min_k(rows, fields, qi, levels)
        rounds += 1

    # Rollback: recover utility by de-generalizing any field that isn't needed.
    if k >= k_threshold:
        improved = True
        while improved:
            improved = False
            for f in fields:
                if levels[f] > 0:
                    levels[f] -= 1
                    if _min_k(rows, fields, qi, levels) >= k_threshold:
                        improved = True
                    else:
                        levels[f] += 1
        k = _min_k(rows, fields, qi, levels)

    gated = []
    for r in rows:
        nr = dict(r)
        for f in fields:
            if levels[f] > 0:
                nr[f] = qi[f][levels[f]](r.get(f))
        gated.append(nr)

    result = {
        "k": k,
        "threshold": k_threshold,
        "passed": k >= k_threshold,
        "quasi_identifiers": fields,
        "generalized": {f: levels[f] for f in fields if levels[f] > 0},
    }
    return gated, result
