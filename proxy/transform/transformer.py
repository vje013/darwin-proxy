"""Transform layer. Applies operators to a Table given a detection mapping.

transform_table pseudonymizes identifier columns and passes quasi-identifier
columns through untouched (the gate handles those). transform_cell handles
free-text narrative via the text anonymizer. Commodity operators are reachable by
passing an explicit operators dict (replace/redact/mask/hash/encrypt)."""
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
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

    # ---- reversibility: two modes ----------------------------------------
    # map mode: keyed substitution stays signal-preserving (realistic, joinable)
    #   and is reversible only via the encrypted, TTL-bound MapStore.
    # encrypt mode: Presidio AES encrypt produces opaque ciphertext, reversible by
    #   key alone with no stored map. Not analyzable, but stateless.

    def reverse_table(self, table, mapping):
        """Reverse keyed (map-mode) substitution via the round-trip MapStore."""
        store = self.substitutor.store
        if store is None:
            raise ValueError("transformer is not in round-trip mode (construct with round_trip=True)")
        to_transform, _ = split_mapping(mapping)
        df = table.df.copy()
        for col, ent in to_transform.items():
            restored = []
            for v in df[col]:
                orig = store.reverse(ent, v)
                restored.append(orig if orig is not None else v)
            df[col] = restored
        return Table(df)

    def save_map(self, path, secret, ttl_seconds=None):
        from proxy.maps import fernet_from_secret
        self.substitutor.store.save(path, fernet_from_secret(secret), ttl_seconds)

    def load_map(self, path, secret):
        from proxy.maps import MapStore, fernet_from_secret
        self.substitutor.store = MapStore.load(path, fernet_from_secret(secret))

    def _aes_key(self, key):
        if key is not None:
            return key
        import hashlib
        return hashlib.sha256(self.substitutor.key).hexdigest()[:32]  # 256-bit

    def encrypt_table(self, table, mapping, key=None):
        """Opaque, stateless reversibility: AES-encrypt identifier columns."""
        to_transform, _ = split_mapping(mapping)
        if not to_transform:
            return Table(table.df.copy()), {}
        k = self._aes_key(key)
        ops = {ent: OperatorConfig("encrypt", {"key": k}) for ent in set(to_transform.values())}
        ops["DEFAULT"] = OperatorConfig("encrypt", {"key": k})
        analysis = StructuredAnalysis(entity_mapping=to_transform)
        out_df = StructuredEngine().anonymize(table.df.copy(), analysis, operators=ops)
        return Table(out_df), to_transform

    def decrypt_table(self, table, mapping, key=None):
        from presidio_anonymizer.operators import Decrypt
        to_transform, _ = split_mapping(mapping)
        k = self._aes_key(key)
        op = Decrypt()
        df = table.df.copy()
        for col in to_transform:
            df[col] = [op.operate(text=v, params={"key": k}) if v else v for v in df[col]]
        return Table(df)
