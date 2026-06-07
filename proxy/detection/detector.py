"""Content-based detection.

analyze_table classifies columns by their values, not their header names, using
presidio-structured over the shared analyzer. scan_cell analyzes free text inside
a cell for the narrative path. An override policy pins or suppresses columns:
override {col: "PERSON"} forces a type, {col: None} forces the column to be kept.

Bias is toward detection: over-flagging a benign numeric column is over-redaction,
the safe failure mode, and the override exists to pin such a column back to keep.
"""
from proxy.detection.engine import build_analyzer


class Detector:
    def __init__(self, nlp_engine=None, model=None, languages=("en",),
                 score_threshold=0.5, finance=True):
        self._build_kwargs = dict(nlp_engine=nlp_engine, model=model,
                                  languages=languages, finance=finance)
        self.score_threshold = score_threshold
        self._analyzer = None

    @property
    def analyzer(self):
        if self._analyzer is None:
            self._analyzer = build_analyzer(**self._build_kwargs)
        return self._analyzer

    def analyze_table(self, table, language="en", override=None,
                      selection_strategy="most_common"):
        from presidio_structured import PandasAnalysisBuilder
        builder = PandasAnalysisBuilder(analyzer=self.analyzer,
                                        analyzer_score_threshold=self.score_threshold)
        analysis = builder.generate_analysis(table.df, language=language,
                                             selection_strategy=selection_strategy)
        mapping = {c: e for c, e in dict(analysis.entity_mapping).items() if e}
        if override:
            for col, ent in override.items():
                if ent is None:
                    mapping.pop(col, None)
                else:
                    mapping[col] = ent
        return {c: e for c, e in mapping.items() if c in table.columns}

    def scan_cell(self, text, language="en", entities=None):
        if not text or not isinstance(text, str):
            return []
        results = self.analyzer.analyze(text=text, language=language,
                                        score_threshold=self.score_threshold, entities=entities)
        return [(r.entity_type, r.start, r.end, float(r.score)) for r in results]
