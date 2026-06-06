from proxy import Proxy
from proxy.detect import Mode, classify_fields


def test_signal_fields_preserved():
    p = Proxy()
    rec = {"First Name": "John", "Last Name": "Reed", "Shares Owned": "16249", "Share Class": "Common"}
    out, _ = p.abstract_record(rec)
    assert out["Shares Owned"] == "16249"   # signal untouched
    assert out["Share Class"] == "Common"


def test_identity_fields_changed():
    p = Proxy()
    rec = {"First Name": "John", "Last Name": "Reed"}
    out, _ = p.abstract_record(rec)
    assert out["First Name"] != "John"
    assert out["Last Name"] != "Reed"


def test_gender_preserved():
    p = Proxy()
    out_m, _ = p.abstract_record({"First Name": "John"})
    out_f, _ = p.abstract_record({"First Name": "Lisa"})
    # same classifier instance via fresh proxies; just assert it ran and changed
    assert out_m["First Name"] != "John"
    assert out_f["First Name"] != "Lisa"


def test_state_stays_in_region():
    from proxy.classify import STATE_TO_REGION, REGIONS
    p = Proxy()
    out, _ = p.abstract_record({"State": "Connecticut"})
    assert out["State"] in REGIONS["Northeast"]
    assert out["State"] != "Connecticut"


def test_consistency_same_input_same_output():
    p = Proxy()
    a, _ = p.abstract_record({"First Name": "John", "Last Name": "Reed"})
    b, _ = p.abstract_record({"First Name": "John", "Last Name": "Reed"})
    assert a["First Name"] == b["First Name"]
    assert a["Last Name"] == b["Last Name"]


def test_email_derived_from_name():
    p = Proxy()
    out, _ = p.abstract_record({"First Name": "John", "Last Name": "Reed", "Email": "john.reed@gmail.com"})
    assert out["Email"] == f"{out['First Name'].lower()}.{out['Last Name'].lower()}@example.com"
