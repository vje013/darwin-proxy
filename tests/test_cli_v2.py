"""Phase 8b: CLI. Model-free by monkeypatching the _build_proxy seam to a
blank-engine Proxy. reverse uses only the Transformer (no model)."""
import spacy
import pytest
from presidio_analyzer.nlp_engine import SpacyNlpEngine

import proxy.cli as cli
from proxy.cert import generate_key
from proxy.orchestrator import Proxy

CSV = "email,state\na@x.com,Texas\nb@y.com,Texas\nc@z.com,Ohio\nd@w.com,Ohio\n"


class _Blank(SpacyNlpEngine):
    def __init__(self):
        super().__init__(models=[{"lang_code": "en", "model_name": "en_core_web_lg"}])
        self.nlp = {"en": spacy.blank("en")}


@pytest.fixture(autouse=True)
def _inject_blank_proxy(monkeypatch):
    def fake_build(args):
        return Proxy(nlp_engine=_Blank(), signing_key=generate_key(),
                     k_threshold=getattr(args, "k", 5),
                     round_trip=(getattr(args, "mode", "oneway") == "map"))
    monkeypatch.setattr(cli, "_build_proxy", fake_build)


def test_abstract_writes_output_and_cert(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text(CSV)
    out = str(tmp_path / "out.csv")
    assert cli.main(["abstract", str(src), "-o", out]) == 0
    assert (tmp_path / "out.csv").exists()
    assert (tmp_path / "out.csv.manifest.json").exists()


def test_verify_command_exit_zero(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text(CSV)
    out = str(tmp_path / "out.csv")
    cli.main(["abstract", str(src), "-o", out])
    with pytest.raises(SystemExit) as e:
        cli.main(["verify", out + ".manifest.json", "--output", out])
    assert e.value.code == 0


def test_no_sign_produces_unsigned_cert(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text(CSV)
    out = str(tmp_path / "out.csv")
    cli.main(["abstract", str(src), "-o", out, "--no-sign"])
    import json
    m = json.loads((tmp_path / "out.csv.manifest.json").read_text())
    assert m["signature"] == ""


def test_map_mode_abstract_then_reverse(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXY_MAP_SECRET", "s3cret")
    src = tmp_path / "in.csv"
    src.write_text(CSV)
    out = str(tmp_path / "out.csv")
    cli.main(["abstract", str(src), "-o", out, "--mode", "map"])
    assert (tmp_path / "out.csv.map.enc").exists()
    rev = str(tmp_path / "rev.csv")
    cli.main(["reverse", out, "-o", rev, "--manifest", out + ".manifest.json",
              "--map", out + ".map.enc"])
    import pandas as pd
    restored = pd.read_csv(rev, dtype=str)
    assert list(restored["email"]) == ["a@x.com", "b@y.com", "c@z.com", "d@w.com"]


def test_abstract_json_output(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text(CSV)
    out = str(tmp_path / "out.json")
    cli.main(["abstract", str(src), "-o", out])
    assert (tmp_path / "out.json").exists()
    assert (tmp_path / "out.json.manifest.json").exists()
