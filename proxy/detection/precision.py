"""Precision refinement over the structured column mapping.

The real NER model mislabels columns the structured aggregation then trusts: a
column of SSNs reads as DATE_TIME, a column of plain integers reads as DATE_TIME
or PHONE_NUMBER. Left alone, an identifier typed as DATE_TIME is KEPT (not
substituted) and can leak. This pass applies two safe corrections:

1. Precise-identifier veto: if a strong majority of a column's values match a
   strict identifier (email, SSN, ABA/CUSIP/ISIN checksum, Luhn card), that type
   wins over any NER or loose-pattern guess. A strict match is high precision, an
   NER guess on the same values is not.
2. Date false-positive demotion: a column typed DATE_TIME whose values are bare
   integers is not a date, so it is demoted to signal (unmapped). Date-shaped
   values (with separators) are left as DATE_TIME.

Both directions are conservative: the veto only fires on strict matches, and the
demotion only drops a DATE_TIME label that is provably wrong.
"""
import re

from proxy.recognizers import aba_valid, cusip_valid, isin_valid

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")  # shape for column typing, not per-value validity
_CARD = re.compile(r"^\d{13,19}$")
_BARE_INT = re.compile(r"^\d+$")

_SAMPLE = 200
_THRESHOLD = 0.8


def _luhn(s):
    digits = [int(c) for c in s]
    checksum = sum(digits[-1::-2])
    for d in digits[-2::-2]:
        checksum += sum(divmod(d * 2, 10))
    return checksum % 10 == 0


def _card(v):
    return bool(_CARD.match(v)) and _luhn(v)


# Order matters: most specific / least ambiguous first.
_PRECISE = [
    ("EMAIL_ADDRESS", lambda v: bool(_EMAIL.match(v))),
    ("US_SSN", lambda v: bool(_SSN.match(v))),
    ("US_ABA_ROUTING", aba_valid),
    ("ISIN", isin_valid),
    ("CUSIP", cusip_valid),
    ("CREDIT_CARD", _card),
]


def refine_mapping(table, mapping, threshold=_THRESHOLD):
    out = dict(mapping)
    for col in table.columns:
        vals = [v for v in table.df[col].tolist() if v][:_SAMPLE]
        if not vals:
            continue
        vetoed = False
        for ent, test in _PRECISE:
            if sum(bool(test(v)) for v in vals) / len(vals) >= threshold:
                out[col] = ent
                vetoed = True
                break
        if vetoed:
            continue
        # demote DATE_TIME on bare integers (a bare int is not a date)
        if out.get(col) == "DATE_TIME" and all(_BARE_INT.match(v) for v in vals):
            out.pop(col, None)
    return out
