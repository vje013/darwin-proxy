"""The Proxy pipeline. abstract_record() for one dict, abstract_csv() for a file.
Output: abstracted data + an AbstractionManifest (the cert-to-be).

The gate runs as a reduce step over the whole abstracted dataset, so it lives
in abstract_csv, not abstract_record.
"""
import csv
import hashlib

from proxy.detect import classify_fields, Mode
from proxy.classify import SemanticClassifier
from proxy.substitute import Substitutor
from proxy.gate import apply_gate
from proxy.schemas import AbstractionManifest


class Proxy:
    def __init__(self, seed=42):
        self.classifier = SemanticClassifier()
        self.substitutor = Substitutor(seed=seed)

    def abstract_record(self, record, policy=None):
        modes = classify_fields(record, policy)
        out, semantic_classes, context = {}, [], {}

        # Pass 1: semantic + format + signal
        for field, value in record.items():
            entity_type, mode = modes[field]
            if mode == Mode.SIGNAL:
                out[field] = value
            elif mode == Mode.SEMANTIC:
                sc = self.classifier.classify(field, entity_type, value)
                repl = self.substitutor.substitute(field, entity_type, value, sc)
                out[field] = repl
                semantic_classes.append(sc)
                context[field] = repl
            elif mode == Mode.FORMAT:
                out[field] = self.substitutor.substitute_format(field, entity_type, value)

        # Pass 2: derived (e.g. email from the fake first/last)
        for field, value in record.items():
            entity_type, mode = modes[field]
            if mode == Mode.DERIVED:
                out[field] = self.substitutor.derive_email(field, value, context)

        return out, semantic_classes

    def abstract_csv(self, input_path, output_path, policy=None, k_threshold=5):
        with open(input_path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            rows = list(reader)

        modes = classify_fields(rows[0], policy) if rows else {}
        out_rows, all_classes = [], []
        for row in rows:
            out, scs = self.abstract_record(row, policy)
            out_rows.append(out)
            all_classes.extend(scs)

        # Reduce step: enforce k-anonymity across the abstracted dataset.
        out_rows, gate_result = apply_gate(out_rows, k_threshold=k_threshold)

        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(out_rows)

        abstracted = [f for f, (_, m) in modes.items() if m != Mode.SIGNAL]
        preserved = [f for f, (_, m) in modes.items() if m == Mode.SIGNAL]

        manifest = AbstractionManifest(
            policy="finance-default",
            records=len(rows),
            fields_abstracted=abstracted,
            fields_preserved=preserved,
            semantic_classes=all_classes[:50],
            gate_result=gate_result,
            before_hash=_sha256(input_path),
            after_hash=_sha256(output_path),
        )
        return manifest, rows, out_rows


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()
