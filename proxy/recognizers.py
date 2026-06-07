"""Finance entity recognizers for Presidio.

Presidio PatternRecognizers with checksum validation. ABA routing, CUSIP, and
ISIN validate their check digits in validate_result, so a structurally-shaped but
invalid number is dropped, not flagged. SSN excludes structurally invalid forms.
EIN and account numbers carry no checksum; they are scored to pass the engine's
threshold but gated on context by the scanner (CONTEXT_REQUIRED), so they only
fire when a tax-id / account keyword is nearby.
"""
from presidio_analyzer import Pattern, PatternRecognizer

_CUSIP_VALS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ*@#"
_VALID_ABA_PREFIX = set(range(0, 13)) | set(range(21, 33)) | set(range(61, 73)) | {80}


def aba_valid(d):
    if len(d) != 9 or not d.isdigit():
        return False
    if int(d[:2]) not in _VALID_ABA_PREFIX:
        return False
    s = (3 * (int(d[0]) + int(d[3]) + int(d[6]))
         + 7 * (int(d[1]) + int(d[4]) + int(d[7]))
         + (int(d[2]) + int(d[5]) + int(d[8])))
    return s % 10 == 0 and s > 0


def cusip_valid(c):
    if len(c) != 9:
        return False
    s = 0
    for i, ch in enumerate(c[:8]):
        if ch not in _CUSIP_VALS:
            return False
        v = _CUSIP_VALS.index(ch)
        if i % 2 == 1:
            v *= 2
        s += v // 10 + v % 10
    return c[8].isdigit() and (10 - s % 10) % 10 == int(c[8])


def isin_valid(c):
    if len(c) != 12 or not c[:2].isalpha():
        return False
    body = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in c)
    try:
        digits = [int(x) for x in body]
    except ValueError:
        return False
    s, dbl = 0, True
    for x in reversed(digits[:-1]):
        x = x * 2 if dbl else x
        s += x - 9 if x > 9 else x
        dbl = not dbl
    return (10 - s % 10) % 10 == digits[-1]


class AbaRoutingRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(supported_entity="US_ABA_ROUTING",
                         patterns=[Pattern("aba", r"\b\d{9}\b", 0.4)],
                         context=["routing", "aba", "rtn", "wire", "ach", "bank"])

    def validate_result(self, pattern_text):
        return aba_valid(pattern_text)


class CusipRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(supported_entity="CUSIP",
                         patterns=[Pattern("cusip", r"\b[0-9A-Z]{9}\b", 0.3)],
                         context=["cusip", "security", "securities"])

    def validate_result(self, pattern_text):
        return cusip_valid(pattern_text)


class IsinRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(supported_entity="ISIN",
                         patterns=[Pattern("isin", r"\b[A-Z]{2}[0-9A-Z]{9}[0-9]\b", 0.3)],
                         context=["isin", "security", "securities"])

    def validate_result(self, pattern_text):
        return isin_valid(pattern_text)


class SsnRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(supported_entity="US_SSN",
                         patterns=[Pattern("ssn",
                             r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", 0.6)],
                         context=["ssn", "social security"])


class EinRecognizer(PatternRecognizer):
    # Base score above threshold so it survives to the scanner's context gate.
    def __init__(self):
        super().__init__(supported_entity="US_EIN",
                         patterns=[Pattern("ein", r"\b\d{2}-\d{7}\b", 0.5)],
                         context=["ein", "employer identification", "tax id", "tin", "federal tax"])


class AccountRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(supported_entity="FIN_ACCOUNT",
                         patterns=[Pattern("acct", r"\b\d{8,17}\b", 0.5)],
                         context=["account", "acct", "a/c", "account no", "account number"])


# No-checksum entities: require nearby context to fire (deterministic precision gate).
CONTEXT_REQUIRED = {"US_EIN", "FIN_ACCOUNT", "CUSIP"}

FINANCE_ENTITIES = ["US_SSN", "US_ABA_ROUTING", "CUSIP", "ISIN", "US_EIN", "FIN_ACCOUNT"]


def finance_recognizers():
    return [SsnRecognizer(), AbaRoutingRecognizer(), CusipRecognizer(),
            IsinRecognizer(), EinRecognizer(), AccountRecognizer()]
