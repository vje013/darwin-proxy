"""The Proxy pipeline.

  _abstract_record  one record, given a substitutor (per-call isolation)
  abstract_record   one record using the Proxy's own substitutor (convenience)
  abstract_rows     in-memory dataset -> (manifest, rows, substitutor)  [API core]
  abstract_csv      file -> file, delegating to abstract_rows           [CLI]

Column policy handles structured fields; the FinanceScanner handles inline PII in
free-text SIGNAL fields; the re-id gate runs last as a reduce over the dataset;
the manifest is signed. Models (scanner, classifier) are shared and expensive; the
substitutor is per-call so concurrent requests never share pseudonym state.
"""
import csv
import hashlib
import json

from proxy.detect import classify_fields, Mode, FinanceScanner, redact_inline
from proxy.classify import SemanticClassifier
from proxy.substitute import Substitutor
from proxy.gate import apply_gate
from proxy.cert import sign_manifest, load_or_create_key
from proxy.schemas import AbstractionManifest


class Proxy:
    def __init__(self, seed=42, scanner=None, key=None, round_trip=False):
        self.classifier = SemanticClassifier()
        self.scanner = scanner if scanner is not None else FinanceScanner()
        self._key = key
        self._round_trip = round_trip
        self.substitutor = Substitutor(key=key, round_trip=round_trip)

    def _abstract_record(self, record, sub, policy=None):
        modes = classify_fields(record, policy)
        out, semantic_classes, context = {}, [], {}

        for field, value in record.items():
            entity_type, mode = modes[field]
            if mode == Mode.SIGNAL:
                out[field] = value
            elif mode == Mode.SEMANTIC:
                sc = self.classifier.classify(field, entity_type, value)
                out[field] = sub.substitute(field, entity_type, value, sc)
                semantic_classes.append(sc)
                context[field] = out[field]
            elif mode == Mode.FORMAT:
                out[field] = sub.substitute_format(field, entity_type, value)

        for field, value in record.items():
            entity_type, mode = modes[field]
            if mode == Mode.DERIVED:
                out[field] = sub.derive_email(field, value, context)

        inline_spans = []
        for field, value in record.items():
            _, mode = modes[field]
            if mode == Mode.SIGNAL and isinstance(value, str):
                spans = self.scanner.scan(value)
                if spans:
                    out[field] = redact_inline(value, spans)
                    inline_spans.extend(spans)

        return out, semantic_classes, inline_spans

    def abstract_record(self, record, policy=None):
        return self._abstract_record(record, self.substitutor, policy)

    def abstract_rows(self, rows, policy=None, k_threshold=5, sign=True, sign_key=None,
                      pseudonym_key=None, round_trip=False):
        sub = Substitutor(key=pseudonym_key, round_trip=round_trip)
        modes = classify_fields(rows[0], policy) if rows else {}
        out_rows, all_classes, inline_counts = [], [], {}
        for row in rows:
            out, scs, spans = self._abstract_record(row, sub, policy)
            out_rows.append(out)
            all_classes.extend(scs)
            for s in spans:
                inline_counts[s.entity_type] = inline_counts.get(s.entity_type, 0) + 1

        out_rows, gate_result = apply_gate(out_rows, k_threshold=k_threshold)

        manifest = AbstractionManifest(
            policy="finance-default",
            records=len(rows),
            fields_abstracted=[f for f, (_, m) in modes.items() if m != Mode.SIGNAL],
            fields_preserved=[f for f, (_, m) in modes.items() if m == Mode.SIGNAL],
            semantic_classes=all_classes[:50],
            gate_result=gate_result,
            inline_redactions=inline_counts or None,
            before_hash=_rows_hash(rows),
            after_hash=_rows_hash(out_rows),
        )
        if sign:
            sign_manifest(manifest, sign_key or load_or_create_key())
        return manifest, out_rows, sub

    def abstract_csv(self, input_path, output_path, policy=None, k_threshold=5, sign=True, key=None,
                     map_path=None, map_secret=None, ttl_seconds=None):
        with open(input_path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            rows = list(reader)

        manifest, out_rows, sub = self.abstract_rows(
            rows, policy=policy, k_threshold=k_threshold, sign=sign, sign_key=key,
            pseudonym_key=self._key, round_trip=self._round_trip)

        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(out_rows)

        if self._round_trip and map_path and map_secret:
            from proxy.maps import fernet_from_secret
            sub.store.save(map_path, fernet_from_secret(map_secret), ttl_seconds)
        return manifest, rows, out_rows


def _rows_hash(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()
