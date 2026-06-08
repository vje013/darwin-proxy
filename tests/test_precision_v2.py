"""P0.5: detection precision. refine_mapping corrects the real-model mislabels the
benchmark surfaced (SSN typed DATE_TIME, signal integers typed DATE_TIME/PHONE) so
identifiers are not silently kept-and-leaked. Tested as a pure function plus a
real-model end-to-end assertion that runs on the host."""
import pandas as pd
import pytest
import spacy.util

from proxy.detection.precision import refine_mapping
from proxy.ingest import Table


def _t(**cols):
    return Table(pd.DataFrame(cols))


def test_ssn_mislabeled_date_is_corrected():
    t = _t(ssn=["123-45-6789", "987-65-4320", "078-05-1120"])
    assert refine_mapping(t, {"ssn": "DATE_TIME"}) == {"ssn": "US_SSN"}  # the leak fix


def test_bare_int_date_is_demoted_to_signal():
    t = _t(shares=["16249", "39024", "24104"])
    assert refine_mapping(t, {"shares": "DATE_TIME"}) == {}  # not a date -> signal


def test_real_date_column_is_preserved():
    t = _t(acq=["2021-01-01", "2020-06-30", "2019-03-15"])
    assert refine_mapping(t, {"acq": "DATE_TIME"}) == {"acq": "DATE_TIME"}  # genuine date kept


def test_email_and_routing_veto_over_loose_labels():
    t = _t(email=["a@x.com", "b@y.com"], routing=["021000021", "011401533"])
    out = refine_mapping(t, {"email": "PHONE_NUMBER", "routing": "DATE_TIME"})
    assert out == {"email": "EMAIL_ADDRESS", "routing": "US_ABA_ROUTING"}


def test_person_and_location_left_alone():
    t = _t(name=["John Smith", "Jane Doe"], state=["Texas", "Ohio"])
    out = refine_mapping(t, {"name": "PERSON", "state": "LOCATION"})
    assert out == {"name": "PERSON", "state": "LOCATION"}  # no precise match, not demoted


def test_veto_adds_missed_identifier():
    # structured missed it; strict shape recovers it (recall improvement)
    t = _t(x=["123-45-6789", "078-05-1120"])
    assert refine_mapping(t, {}) == {"x": "US_SSN"}


def test_phone_on_numeric_left_as_is():
    # PHONE on bare ints is over-redaction (safe direction); only DATE_TIME is demoted
    t = _t(num=["5551234567", "5559876543"])
    assert refine_mapping(t, {"num": "PHONE_NUMBER"}) == {"num": "PHONE_NUMBER"}


@pytest.mark.skipif(not spacy.util.is_package("en_core_web_lg"),
                    reason="needs en_core_web_lg (host only)")
def test_realmodel_ssn_types_correctly_end_to_end():
    from proxy.detection import Detector
    t = _t(ssn=["123-45-6789", "987-65-4320", "078-05-1120", "111-22-3333"],
           shares=["16249", "39024", "24104", "55012"],
           name=["John Smith", "Jane Doe", "Robert Lee", "Mary Poe"])
    m = Detector().analyze_table(t)
    assert m.get("ssn") == "US_SSN"      # not DATE_TIME -> will be substituted, not kept
    assert "shares" not in m             # signal, not a date QI
    assert m.get("name") == "PERSON"
