"""Phase 8b: HTTP service. Model-free via a dependency override that injects a
blank-engine Proxy."""
import spacy
from fastapi.testclient import TestClient
from presidio_analyzer.nlp_engine import SpacyNlpEngine

from proxy.cert import generate_key
from proxy.orchestrator import Proxy
from proxy.service import app, get_proxy


class _Blank(SpacyNlpEngine):
    def __init__(self):
        super().__init__(models=[{"lang_code": "en", "model_name": "en_core_web_lg"}])
        self.nlp = {"en": spacy.blank("en")}


_BP = None


def _proxy_override():
    global _BP
    if _BP is None:
        _BP = Proxy(nlp_engine=_Blank(), signing_key=generate_key(), k_threshold=2)
    return _BP


app.dependency_overrides[get_proxy] = _proxy_override
client = TestClient(app)

CSV = "email,state\na@x.com,Texas\nb@y.com,Texas\nc@z.com,Ohio\nd@w.com,Ohio\n"


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_abstract_then_verify_roundtrip():
    r = client.post("/abstract", json={"csv": CSV, "mode": "oneway"})
    assert r.status_code == 200
    body = r.json()
    assert "a@x.com" not in body["output_csv"]            # email substituted
    assert body["manifest"]["schema_version"] == 2
    assert body["manifest"]["detection"]["email"] == "EMAIL_ADDRESS"

    v = client.post("/verify", json={"manifest": body["manifest"], "output_csv": body["output_csv"]})
    assert v.status_code == 200
    assert v.json()["valid"] is True


def test_abstract_encrypt_is_opaque():
    r = client.post("/abstract", json={"csv": CSV, "mode": "encrypt"})
    body = r.json()
    first_email = body["output_csv"].splitlines()[1].split(",")[0]
    assert "@" not in first_email
    assert body["manifest"]["operators"]["EMAIL_ADDRESS"] == "encrypt"


def test_abstract_rejects_map_mode():
    r = client.post("/abstract", json={"csv": CSV, "mode": "map"})
    assert r.status_code == 400


def test_metrics_counts():
    before = client.get("/metrics").json()["abstract"]
    client.post("/abstract", json={"csv": CSV, "mode": "oneway"})
    assert client.get("/metrics").json()["abstract"] == before + 1


def test_abstract_bad_input_returns_400():
    r = client.post("/abstract", json={"csv": "", "mode": "oneway"})  # empty -> parse error
    assert r.status_code == 400


def test_verify_bad_manifest_returns_400():
    r = client.post("/verify", json={"manifest": {"records": "not-an-int"}, "output_csv": "a\n1\n"})
    assert r.status_code == 400
