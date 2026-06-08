"""v2 orchestrator. One call runs the whole pipeline:

    ingest -> detect (content-based) -> transform (keyed or encrypt)
           -> gate (k-anonymity over inferred QIs) -> certify (signed manifest)

Ordering matters. Transform substitutes identifier columns and leaves quasi-identifier
columns (geography, dates) in place; the gate then generalizes those QIs on the
transformed table, so the signed output reflects both steps. The manifest binds the
detection mapping, operators, reversibility mode, and the full gate result.
"""
from proxy.certify import build_manifest
from proxy.detection import Detector
from proxy.gate import apply_gate_table
from proxy.ingest import Table, read
from proxy.transform import Transformer


class Proxy:
    def __init__(self, key=None, language="en", k_threshold=5, round_trip=False,
                 nlp_engine=None, score_threshold=0.5, signing_key=None, batch_size=32):
        self.language = language
        self.k_threshold = k_threshold
        self.detector = Detector(nlp_engine=nlp_engine, languages=(language,),
                                 score_threshold=score_threshold, batch_size=batch_size)
        self.transformer = Transformer(key=key, round_trip=round_trip)
        self._signing_key = signing_key

    def abstract_table(self, table, *, reversibility="oneway", qi_config=None,
                       require_qi=True, override=None, sign=True, source_format=None):
        mapping = self.detector.analyze_table(table, language=self.language, override=override)

        if reversibility == "encrypt":
            transformed_tbl, transformed = self.transformer.encrypt_table(table, mapping)
            operators = {ent: "encrypt" for ent in set(transformed.values())}
        else:
            transformed_tbl, transformed = self.transformer.transform_table(table, mapping)
            operators = {ent: "keyed_substitute" for ent in set(transformed.values())}

        gated, gate_result = apply_gate_table(
            transformed_tbl, mapping=mapping, qi_config=qi_config,
            k_threshold=self.k_threshold, require_qi=require_qi)

        kept = [c for c in table.columns if c not in transformed]
        manifest = build_manifest(
            records=table.n_rows, source_format=source_format or table.source_format,
            language=self.language, detection=mapping, kept_columns=kept,
            operators=operators, reversibility=reversibility,
            gate_result=gate_result, before_table=table, after_table=gated)
        if sign:
            from proxy.cert import sign_manifest
            sign_manifest(manifest, self._key())
        return gated, manifest

    def abstract_file(self, in_path, out_path, **kwargs):
        table = read(in_path)
        gated, manifest = self.abstract_table(table, **kwargs)
        if out_path.endswith(".json"):
            gated.df.to_json(out_path, orient="records", indent=2)
        else:
            gated.df.to_csv(out_path, index=False)
        with open(out_path + ".manifest.json", "w") as f:
            f.write(manifest.model_dump_json(indent=2))
        return out_path, manifest

    def reverse_table(self, table, manifest):
        """Restore substituted identifiers (map mode). Generalized QIs stay
        generalized: that loss is intentional and irreversible."""
        return self.transformer.reverse_table(table, manifest.detection)

    def _key(self):
        if self._signing_key is not None:
            return self._signing_key
        from proxy.cert import load_or_create_key
        return load_or_create_key()
