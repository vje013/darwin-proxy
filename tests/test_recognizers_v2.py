"""Phase 9: direct coverage of the finance checksum validators and their
validate_result wiring. Each validator is exercised on valid and invalid inputs
(length, character set, prefix, checksum)."""
from proxy.recognizers import (AbaRoutingRecognizer, CusipRecognizer, IsinRecognizer,
                              aba_valid, cusip_valid, finance_recognizers, isin_valid)


def test_aba_valid_and_invalid():
    assert aba_valid("021000021") is True            # JPMorgan
    assert aba_valid("011401533") is True
    assert aba_valid("12345678") is False             # wrong length
    assert aba_valid("02100002X") is False            # non-digit
    assert aba_valid("990000000") is False            # prefix out of range
    assert aba_valid("021000022") is False            # checksum fails


def test_cusip_valid_and_invalid():
    assert cusip_valid("037833100") is True           # Apple
    assert cusip_valid("0378331") is False            # wrong length
    assert cusip_valid("0378!3100") is False          # char outside CUSIP alphabet (in body)
    assert cusip_valid("037833101") is False          # checksum fails


def test_isin_valid_and_invalid():
    assert isin_valid("US0378331005") is True         # Apple ISIN
    assert isin_valid("US037833100") is False         # wrong length
    assert isin_valid("120378331005") is False        # first two not alpha
    assert isin_valid("US037833100!") is False        # non-convertible body char
    assert isin_valid("US0378331004") is False        # checksum fails


def test_validate_result_wiring():
    assert AbaRoutingRecognizer().validate_result("021000021") is True
    assert AbaRoutingRecognizer().validate_result("021000022") is False
    assert CusipRecognizer().validate_result("037833100") is True
    assert IsinRecognizer().validate_result("US0378331005") is True


def test_finance_recognizers_set():
    ents = {r.supported_entities[0] for r in finance_recognizers()}
    assert ents == {"US_SSN", "US_ABA_ROUTING", "CUSIP", "ISIN", "US_EIN", "FIN_ACCOUNT"}
