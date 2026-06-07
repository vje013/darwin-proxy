"""Phase 6: image redaction over OCR, with graceful degradation. The unavailable
path runs everywhere; the real-redaction tests need tesseract + [images] and skip
otherwise. Model-free via the blank engine, so assertions use pattern entities."""
import numpy as np
import pytest
from PIL import Image, ImageDraw, ImageFont

import proxy.images.redactor as redactor_mod
from proxy.images import ImageRedactionUnavailable, ImageRedactor, available

requires_ocr = pytest.mark.skipif(not available(), reason="needs tesseract-ocr + [images] extra")


def _blank_redactor():
    import spacy
    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    class Blank(SpacyNlpEngine):
        def __init__(self):
            super().__init__(models=[{"lang_code": "en", "model_name": "en_core_web_lg"}])
            self.nlp = {"en": spacy.blank("en")}
    return ImageRedactor(nlp_engine=Blank())


def _img(text):
    im = Image.new("RGB", (760, 90), "white")
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 40)
    except Exception:
        font = ImageFont.load_default()
    ImageDraw.Draw(im).text((15, 25), text, fill="black", font=font)
    return im


def test_unavailable_raises_clearly(monkeypatch):
    monkeypatch.setattr(redactor_mod, "available", lambda: False)
    with pytest.raises(ImageRedactionUnavailable):
        ImageRedactor()


@requires_ocr
def test_email_redacted_from_image():
    import pytesseract
    img = _img("Contact alice@acme.com today")
    assert "alice@acme.com" in pytesseract.image_to_string(img)   # present before
    out = _blank_redactor().redact_image(img)
    assert "alice@acme.com" not in pytesseract.image_to_string(out)  # gone after
    assert (np.asarray(img) != np.asarray(out)).any()                # box drawn


@requires_ocr
def test_no_pii_leaves_image_untouched():
    img = _img("Quarterly revenue rose nine percent")
    out = _blank_redactor().redact_image(img)
    assert int((np.asarray(img) != np.asarray(out)).any(axis=2).sum()) == 0  # no false boxes


@requires_ocr
def test_redact_file_writes_output(tmp_path):
    p, q = tmp_path / "in.png", tmp_path / "out.png"
    _img("Contact alice@acme.com today").save(p)
    _blank_redactor().redact_file(str(p), str(q))
    assert q.exists() and Image.open(q).size == (760, 90)
