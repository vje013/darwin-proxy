"""Build and re-check the v2 certificate.

The split that gives the certificate its value: some claims are re-checkable from
the signed output alone (the signature binds the manifest; the output hash binds
the artifact; k-anonymity can be recomputed over the recorded quasi-identifiers).
Others are not (whether signal-preserving substitution is *adequate* de-id is a
statistical judgment, which is exactly why an authority stamp has worth). recheck
verifies the first kind hard and reports the second kind honestly, and it never
claims k-anonymity the gate flagged as unassessed.
"""
import hashlib
from collections import Counter

from proxy.cert import verify_manifest
from proxy.schemas_v2 import AbstractionManifestV2

SEMANTIC_MODES = {"oneway", "map"}


def hash_table(table):
    return hashlib.sha256(table.df.to_csv(index=False).encode("utf-8")).hexdigest()


def build_manifest(*, records, detection, kept_columns, operators, reversibility,
                   gate_result, before_table, after_table, source_format="dataframe",
                   language="en", policy="content-based"):
    return AbstractionManifestV2(
        records=records, source_format=source_format, language=language, policy=policy,
        detection=dict(detection), kept_columns=list(kept_columns),
        operators=dict(operators), reversibility=reversibility, gate=gate_result,
        before_hash=hash_table(before_table), after_hash=hash_table(after_table))


def _recompute_k(table, qis):
    qis = [q for q in qis if q in table.columns]
    if not qis:
        return 0
    rows = table.to_rows()
    counts = Counter(tuple(r.get(q, "") for q in qis) for r in rows)
    return min(counts.values()) if counts else 0


def recheck(manifest, output_table, darwin_root=None):
    sig = verify_manifest(manifest, darwin_root)
    hash_ok = hash_table(output_table) == manifest.after_hash

    g = manifest.gate or {}
    if not g.get("assessed", False):
        k_report = {"assessed": False, "certified": False,
                    "reason": g.get("reason") or "gate did not assess quasi-identifiers"}
    else:
        rk = _recompute_k(output_table, g.get("quasi_identifiers", []))
        thr = g.get("threshold", 0)
        k_report = {"assessed": True, "certified": rk >= thr, "recomputed_k": rk,
                    "claimed_k": g.get("k"), "matches_claim": rk == g.get("k"), "threshold": thr}

    if manifest.reversibility in SEMANTIC_MODES:
        note = ("signal-preserving substitution keeps entity shape by design, so "
                "type re-detection is expected and is not a leak; de-identification "
                "adequacy is an authority judgment, not re-derivable from the output")
    else:
        note = "opaque tokens; original values are not recoverable from the output without the key"

    return {
        "schema_version": manifest.schema_version,
        "signature": sig,
        "integrity": {"output_hash_matches": hash_ok, "valid": sig["valid"] and hash_ok},
        "k_anonymity": k_report,
        "deidentification": {"mode": manifest.reversibility, "note": note},
        "valid": sig["valid"] and hash_ok,
    }
