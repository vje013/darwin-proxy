"""Image redaction. OCR (Tesseract) lifts text from an image, our analyzer finds
PII in that text, and the redactor paints fill boxes over the detected regions.

Fidelity is bounded by OCR: text the OCR mangles is text the analyzer never sees,
so it cannot be redacted. This degrades safely (a missed box, never a crash) but
is a real limit. Callers handling sensitive imagery must not treat a redacted
image as a guarantee of zero residual PII.

The capability is optional: it needs the [images] extra and the system
tesseract-ocr binary. available() reports readiness; constructing ImageRedactor
without it raises ImageRedactionUnavailable rather than failing deep in a call.
"""


class ImageRedactionUnavailable(RuntimeError):
    pass


def available():
    try:
        import presidio_image_redactor  # noqa: F401
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


class ImageRedactor:
    def __init__(self, analyzer=None, nlp_engine=None, languages=("en",)):
        if not available():
            raise ImageRedactionUnavailable(
                "image redaction needs the [images] extra and the tesseract-ocr system package")
        from presidio_image_redactor import ImageAnalyzerEngine, ImageRedactorEngine

        from proxy.detection.engine import build_analyzer
        analyzer = analyzer or build_analyzer(nlp_engine=nlp_engine, languages=languages)
        self._engine = ImageRedactorEngine(
            image_analyzer_engine=ImageAnalyzerEngine(analyzer_engine=analyzer))

    def redact_image(self, image, fill=(0, 0, 0), language="en", **analyzer_kwargs):
        return self._engine.redact(image, fill=fill, language=language, **analyzer_kwargs)

    def redact_file(self, in_path, out_path, fill=(0, 0, 0), language="en", **analyzer_kwargs):
        from PIL import Image
        out = self.redact_image(Image.open(in_path), fill=fill, language=language, **analyzer_kwargs)
        out.save(out_path)
        return out_path
