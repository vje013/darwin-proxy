"""v2 HTTP service on the Proxy orchestrator.

Stateless by design: /abstract supports oneway and encrypt modes (map mode needs a
client-held encrypted map, so it is not a server concern). /verify re-checks a
manifest against a supplied output. The Proxy is provided via a dependency so tests
inject a model-free engine and the host uses the real model.
"""
import io
import json

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from proxy.certify import recheck
from proxy.ingest import Table
from proxy.orchestrator import Proxy
from proxy.schemas_v2 import AbstractionManifestV2

app = FastAPI(title="Darwin Proxy", version="2.1.1")
_METRICS = {"abstract": 0, "verify": 0, "errors": 0}
_PROXY = None


def get_proxy():
    global _PROXY
    if _PROXY is None:
        _PROXY = Proxy()
    return _PROXY


def _read_csv(text):
    return Table(pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False), "csv")


class AbstractRequest(BaseModel):
    csv: str
    mode: str = "oneway"          # oneway | encrypt
    sign: bool = True


class VerifyRequest(BaseModel):
    manifest: dict
    output_csv: str
    darwin_root: str | None = None


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": "2.0.0"}


@app.get("/metrics")
def metrics():
    return dict(_METRICS)


@app.post("/abstract")
def abstract(req: AbstractRequest, proxy: Proxy = Depends(get_proxy)):
    if req.mode not in ("oneway", "encrypt"):
        _METRICS["errors"] += 1
        raise HTTPException(status_code=400,
                            detail="service supports oneway|encrypt; map mode requires a client-held map")
    try:
        table = _read_csv(req.csv)
        out, manifest = proxy.abstract_table(table, reversibility=req.mode, sign=req.sign)
    except Exception as e:  # noqa: BLE001 - normalize to a 400 for the caller
        _METRICS["errors"] += 1
        raise HTTPException(status_code=400, detail=str(e))
    _METRICS["abstract"] += 1
    return {"output_csv": out.df.to_csv(index=False),
            "manifest": json.loads(manifest.model_dump_json())}


@app.post("/verify")
def verify(req: VerifyRequest):
    try:
        manifest = AbstractionManifestV2.model_validate(req.manifest)
        table = _read_csv(req.output_csv)
    except Exception as e:  # noqa: BLE001
        _METRICS["errors"] += 1
        raise HTTPException(status_code=400, detail=str(e))
    _METRICS["verify"] += 1
    return recheck(manifest, table, darwin_root=req.darwin_root)
