"""Darwin Proxy HTTP service (FastAPI).

  POST /abstract  abstract a dataset (csv text or rows), return signed cert + data
  POST /verify    verify a certificate; optionally re-check the k-anonymity claim
  POST /reverse   reverse a pseudonym using a client-held encrypted round-trip map
  GET  /healthz   liveness
  GET  /metrics   operational + product counters

The service is zero-knowledge of round-trip maps at rest: /abstract returns the
encrypted map to the caller, and /reverse takes it back plus the secret. The
server never stores the map or the secret.
"""
import base64
import csv as _csv
import io

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from proxy import metrics
from proxy.cert import verify_manifest
from proxy.gate import apply_gate, DEFAULT_QI, _min_k
from proxy.maps import MapStore, fernet_from_secret, MapExpired
from proxy.schemas import AbstractionManifest

app = FastAPI(title="Darwin Proxy", version="0.1")

_proxy = None


def get_proxy():
    global _proxy
    if _proxy is None:
        from proxy.pipeline import Proxy
        _proxy = Proxy()
    return _proxy


class AbstractRequest(BaseModel):
    csv: str | None = None
    rows: list[dict] | None = None
    k_threshold: int = 5
    round_trip: bool = False
    map_secret: str | None = None
    ttl_seconds: int | None = None


class AbstractResponse(BaseModel):
    manifest: dict
    rows: list[dict]
    csv: str | None = None
    map_b64: str | None = None


class VerifyRequest(BaseModel):
    manifest: dict
    rows: list[dict] | None = None
    darwin_root: str | None = None


class ReverseRequest(BaseModel):
    map_b64: str
    secret: str
    field: str
    value: str


def _parse_csv(text):
    reader = _csv.DictReader(io.StringIO(text))
    return reader.fieldnames, list(reader)


def _to_csv(fieldnames, rows):
    buf = io.StringIO()
    w = _csv.DictWriter(buf, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/metrics")
def get_metrics():
    return metrics.snapshot()


@app.post("/abstract", response_model=AbstractResponse)
def abstract(req: AbstractRequest):
    metrics.inc("abstract_requests")
    if req.round_trip and not req.map_secret:
        raise HTTPException(400, "round_trip requires map_secret")
    fieldnames, rows = (None, req.rows)
    if req.csv is not None:
        fieldnames, rows = _parse_csv(req.csv)
    if not rows:
        raise HTTPException(400, "no rows provided")
    try:
        with metrics.timer("abstract"):
            proxy = get_proxy()
            manifest, out_rows, sub = proxy.abstract_rows(
                rows, k_threshold=req.k_threshold, round_trip=req.round_trip)
    except Exception as e:
        metrics.inc("errors")
        raise HTTPException(500, f"abstract failed: {e}")

    metrics.inc("records_processed", len(rows))
    g = manifest.gate_result or {}
    metrics.inc("gate_pass" if g.get("passed") else "gate_fail")
    for ent, n in (manifest.inline_redactions or {}).items():
        metrics.inc(f"inline_{ent}", n)
    if manifest.signature:
        metrics.inc("certs_signed")

    map_b64 = None
    if req.round_trip:
        blob = sub.store.to_blob(req.ttl_seconds)
        map_b64 = base64.b64encode(fernet_from_secret(req.map_secret).encrypt(blob)).decode()

    out_csv = _to_csv(fieldnames, out_rows) if req.csv is not None else None
    return AbstractResponse(manifest=manifest.model_dump(mode="json"),
                            rows=out_rows, csv=out_csv, map_b64=map_b64)


@app.post("/verify")
def verify(req: VerifyRequest):
    metrics.inc("verify_requests")
    manifest = AbstractionManifest.model_validate(req.manifest)
    r = verify_manifest(manifest, darwin_root=req.darwin_root)
    metrics.inc("verify_valid" if r["valid"] else "verify_invalid")
    # Re-check the k-anonymity claim independently if the rows are supplied.
    recheck = None
    if req.rows is not None:
        fields = [f for f in DEFAULT_QI if req.rows and f in req.rows[0]]
        recomputed_k = _min_k(req.rows, fields, DEFAULT_QI, {f: 0 for f in fields}) if fields else len(req.rows)
        claimed_k = (manifest.gate_result or {}).get("k")
        recheck = {"recomputed_k": recomputed_k, "claimed_k": claimed_k,
                   "k_matches": recomputed_k == claimed_k}
    return {**r, "recheck": recheck}


@app.post("/reverse")
def reverse(req: ReverseRequest):
    metrics.inc("reverse_requests")
    try:
        blob = fernet_from_secret(req.secret).decrypt(base64.b64decode(req.map_b64))
    except Exception:
        metrics.inc("errors")
        raise HTTPException(403, "cannot decrypt map (wrong secret or corrupt)")
    import json
    import time
    data = json.loads(blob)
    exp = data.get("expires_at")
    if exp is not None and time.time() > exp:
        raise HTTPException(410, "map has expired")
    store = MapStore()
    for ns, mp in data["fwd"].items():
        for o, rep in mp.items():
            store.add(ns, o, rep)
    original = store.reverse(req.field, req.value)
    if original is None:
        raise HTTPException(404, "value not found in map")
    return {"original": original}
