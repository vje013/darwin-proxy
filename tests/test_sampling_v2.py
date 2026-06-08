"""P3: opt-in sampling and model selection. Sampling types columns from a sample
(deterministic, random_state fixed by presidio) and is off by default so detection
never silently trades completeness for speed."""
import pandas as pd

from proxy.cert import generate_key
from proxy.detection import Detector
from proxy.ingest import Table
from proxy.orchestrator import Proxy


def _big(n=600):
    return Table(pd.DataFrame({
        "email": [f"u{i}@x.com" for i in range(n)],
        "ssn": ["123-45-6789"] * n,
        "shares": [str(1000 + i) for i in range(n)],
    }))


def test_sampling_off_by_default():
    assert Detector(ner=False).sample_size is None


def test_sampling_types_homogeneous_table_correctly():
    d = Detector(ner=False)
    t = _big()
    full = d.analyze_table(t)
    sampled = d.analyze_table(t, sample_size=50)
    assert sampled == full                         # homogeneous columns type the same from a sample
    assert sampled["email"] == "EMAIL_ADDRESS" and sampled["ssn"] == "US_SSN"


def test_sampling_is_deterministic():
    d = Detector(ner=False)
    t = _big()
    assert d.analyze_table(t, sample_size=40) == d.analyze_table(t, sample_size=40)


def test_proxy_threads_sample_size_and_model():
    px = Proxy(ner=False, signing_key=generate_key(), sample_size=100, model="en_core_web_sm")
    assert px.detector.sample_size == 100
    assert px.detector._build_kwargs["model"] == "en_core_web_sm"
