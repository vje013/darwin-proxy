"""Phase 6: HTTP service endpoints, driven via TestClient with a blank-engine
scanner injected so no model is needed."""
import pytest
from fastapi.testclient import TestClient

import proxy.api as api
from proxy.pipeline import Proxy


@pytest.fixture
def client(scanner):
    api._proxy = Proxy(scanner=scanner)  # inject blank-engine proxy
    return TestClient(api.app)


def _rows():
    return [{"Stockholder ID": f"SH-{i}", "First Name": "John", "Last Name": "Reed",
             "State": "Vermont", "Share Class": "Common", "Shares Owned": str(1000 + i),
             "Acquisition Date": "2025-01-01"} for i in range(6)]


def test_healthz(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_abstract_signs_and_gates(client):
    r = client.post("/abstract", json={"rows": _rows(), "k_threshold": 3}).json()
    assert r["manifest"]["signature"]
    assert r["manifest"]["gate_result"]["passed"] is True
    assert all(row["First Name"] != "John" for row in r["rows"])


def test_verify_endpoint_and_recheck(client):
    a = client.post("/abstract", json={"rows": _rows(), "k_threshold": 3}).json()
    v = client.post("/verify", json={"manifest": a["manifest"], "rows": a["rows"]}).json()
    assert v["valid"] is True and v["root"] == "self"
    assert v["recheck"]["k_matches"] is True  # independently recomputed k matches the cert


def test_verify_detects_tamper(client):
    a = client.post("/abstract", json={"rows": _rows(), "k_threshold": 3}).json()
    m = a["manifest"]
    m["records"] = 999
    v = client.post("/verify", json={"manifest": m}).json()
    assert v["valid"] is False


def test_roundtrip_then_reverse(client):
    a = client.post("/abstract", json={"rows": _rows(), "k_threshold": 3,
                                       "round_trip": True, "map_secret": "s3cret"}).json()
    assert a["map_b64"]
    pseudonym = a["rows"][0]["First Name"]
    rev = client.post("/reverse", json={"map_b64": a["map_b64"], "secret": "s3cret",
                                        "field": "First Name", "value": pseudonym}).json()
    assert rev["original"] == "John"


def test_reverse_wrong_secret(client):
    a = client.post("/abstract", json={"rows": _rows(), "k_threshold": 3,
                                       "round_trip": True, "map_secret": "right"}).json()
    p = a["rows"][0]["First Name"]
    r = client.post("/reverse", json={"map_b64": a["map_b64"], "secret": "wrong",
                                      "field": "First Name", "value": p})
    assert r.status_code == 403


def test_metrics_increment(client):
    client.post("/abstract", json={"rows": _rows(), "k_threshold": 3})
    m = client.get("/metrics").json()
    assert m.get("abstract_requests", 0) >= 1
    assert m.get("records_processed", 0) >= 6
