"""Transform layer. Applies operators to a Table given a detection mapping.

transform_table pseudonymizes identifier columns and passes quasi-identifier
columns through untouched (the gate handles those). transform_cell handles
free-text narrative via the text anonymizer. Commodity operators are reachable by
passing an explicit operators dict (replace/redact/mask/hash/encrypt)."""
from presidio_anonymizer import AnonymizerEngine
from presidio_structured import StructuredAnalysis, StructuredEngine

from proxy.ingest import Table
from proxy.substitute import Substitutor
from proxy.transform.operators import register_operators
from proxy.transform.policy import build_operators, split_mapping


class Transformer:
    def __init__(self, key=None, round_trip=False):
        register_operators()
        self.substitutor = Substitutor(key=key, round_trip=round_trip)

    def transform_table(self, table, mapping, operators=None):
        to_transform, _kept = split_mapping(mapping)
        if not to_transform:
            return Table(table.df.copy()), {}
        ops = operators or build_operators(to_transform.values(), self.substitutor)
        analysis = StructuredAnalysis(entity_mapping=to_transform)
        out_df = StructuredEngine().anonymize(table.df.copy(), analysis, operators=ops)
        return Table(out_df), to_transform

    def transform_cell(self, text, analyzer_results, operators=None):
        if not text:
            return text
        ents = {r.entity_type for r in analyzer_results}
        ops = operators or build_operators(ents, self.substitutor)
        engine = AnonymizerEngine()
        return engine.anonymize(text=text, analyzer_results=list(analyzer_results),
                                operators=ops).text
