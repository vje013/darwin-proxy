"""Re-identification gate. k-anonymity over quasi-identifier combinations,
applied to the abstracted dataset as a reduce step after substitution.

Substitution kills identity by name. A fake-named record is still a fingerprint
if its remaining fields (region, holdings, acquisition window) are unique. The
gate generalizes those quasi-identifiers until every combination is shared by at
least k records, then picks the generalization with the least information loss.

Search: the QI lattice is small (a handful of fields, short ladders), so we
enumerate it exhaustively and choose the minimal-loss combination that clears k.
This is exact, not a greedy heuristic. If the lattice is ever too large
(LATTICE_CAP), fall back to greedy full-domain generalization with rollback.

Quasi-identifiers are linkage vectors (geography, holdings, dates). Low-cardinality
categoricals like Share Class are signal, not QIs, and are left untouched.
"""
import itertools
from collections import Counter

from proxy.classify import STATE_TO_REGION

LATTICE_CAP = 200_000


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


def _year_bucket(span):
    def f(v):
        s = "" if v is None else str(v)
        try:
            y = int(s[:4])
        except (ValueError, TypeError):
            return _suppress(v)
        lo = (y // span) * span
        return f"{lo}-{lo + span - 1}"
    return f


# Per-field generalization ladders. Level 0 = most specific, last = suppressed.
DEFAULT_QI = {
    "State": [_identity, _region, _suppress],
    "Shares Owned": [_identity, _band(10000), _band(50000), _band(100000), _suppress],
    "Acquisition Date": [_identity, _prefix(7), _prefix(4), _year_bucket(5), _suppress],
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


def _lattice_search(rows, fields, qi, k_threshold):
    """Exhaustive: minimal normalized information loss subject to k >= threshold."""
    maxlevel = [len(qi[f]) - 1 for f in fields]
    best = None  # ((loss, -k), levels_dict)
    for combo in itertools.product(*[range(m + 1) for m in maxlevel]):
        levels = dict(zip(fields, combo))
        k = _min_k(rows, fields, qi, levels)
        if k >= k_threshold:
            loss = sum(combo[i] / maxlevel[i] for i in range(len(fields)) if maxlevel[i])
            score = (loss, -k)
            if best is None or score < best[0]:
                best = (score, levels)
    if best is None:
        return None
    return best[1]


def _greedy(rows, fields, qi, k_threshold, max_rounds=64):
    """Fallback for large lattices: widen toward k, then roll back for utility."""
    levels = {f: 0 for f in fields}
    k = _min_k(rows, fields, qi, levels)
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
    return levels


def apply_gate(rows, qi_config=None, k_threshold=5):
    qi = qi_config or DEFAULT_QI
    fields = [f for f in qi if rows and f in rows[0]]

    if not fields:
        k = len(rows)
        result = {"k": k, "threshold": k_threshold, "passed": k >= k_threshold,
                  "quasi_identifiers": [], "generalized": {}}
        return [dict(r) for r in rows], result

    lattice_size = 1
    for f in fields:
        lattice_size *= len(qi[f])

    levels = None
    if lattice_size <= LATTICE_CAP:
        levels = _lattice_search(rows, fields, qi, k_threshold)
    if levels is None:
        levels = _greedy(rows, fields, qi, k_threshold)

    k = _min_k(rows, fields, qi, levels)
    passed = k >= k_threshold

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
        "passed": passed,
        "quasi_identifiers": fields,
        "generalized": {f: levels[f] for f in fields if levels[f] > 0},
    }
    return gated, result


# ---- v2: content-based QI inference + Table gate with trivial-pass guard ----
# The v1 footgun: with no qi_config it falls back to hardcoded header names, so a
# renamed-header dataset produces zero QIs and the gate "passes" with k=len(rows),
# claiming k-anonymity it never checked. v2 infers QIs from the detection mapping
# (by entity, not header) and refuses to certify when no QIs were assessed.

GEO_ENTITIES = {"LOCATION", "GPE", "NRP_LOCATION"}
DATE_ENTITIES = {"DATE_TIME"}


def infer_qi_config(mapping):
    """Build generalization ladders from detected entities, header-agnostic.
    Geography and dates are the linkage vectors that survive substitution."""
    qi = {}
    for col, ent in (mapping or {}).items():
        if ent in GEO_ENTITIES:
            qi[col] = [_identity, _region, _suppress]
        elif ent in DATE_ENTITIES:
            qi[col] = [_identity, _prefix(7), _prefix(4), _year_bucket(5), _suppress]
    return qi


def apply_gate_table(table, mapping=None, qi_config=None, k_threshold=5, require_qi=True):
    """k-anonymity over a Table. QIs come from the detection mapping (inferred by
    entity) unioned with any explicit qi_config. If no QIs are identified the gate
    does NOT silently pass: it records assessed=False and trivial_pass=True so the
    certificate cannot claim k-anonymity that was never measured."""
    import pandas as pd

    from proxy.ingest import Table

    qi = dict(infer_qi_config(mapping))
    if qi_config:
        qi.update(qi_config)
    rows = table.to_rows()
    fields = [f for f in qi if f in table.columns]

    if not fields:
        result = {
            "k": None, "threshold": k_threshold,
            "passed": (not require_qi),
            "assessed": False, "trivial_pass": True,
            "quasi_identifiers": [], "generalized": {},
            "reason": "no quasi-identifiers identified; re-identification risk not assessed",
        }
        return Table(table.df.copy()), result

    lattice_size = 1
    for f in fields:
        lattice_size *= len(qi[f])
    levels = _lattice_search(rows, fields, qi, k_threshold) if lattice_size <= LATTICE_CAP else None
    if levels is None:
        levels = _greedy(rows, fields, qi, k_threshold)

    k = _min_k(rows, fields, qi, levels)
    passed = k >= k_threshold

    cols = list(table.df.columns)
    gated = []
    for r in rows:
        nr = dict(r)
        for f in fields:
            if levels[f] > 0:
                nr[f] = qi[f][levels[f]](r.get(f))
        gated.append(nr)

    result = {
        "k": k, "threshold": k_threshold, "passed": passed,
        "assessed": True, "trivial_pass": False,
        "quasi_identifiers": fields,
        "generalized": {f: levels[f] for f in fields if levels[f] > 0},
        "reason": None,
    }
    return Table(pd.DataFrame(gated, columns=cols)), result
