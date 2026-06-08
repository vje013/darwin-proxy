"""Our keyed signal-preserving substitution, expressed as a Presidio custom
Operator so it plugs into both the structured (column) engine and the text
(cell) engine alongside the commodity operators (replace/redact/mask/hash/encrypt).

The structured path does not inject entity_type into params, so callers must put
it there. A shared Substitutor is passed in params so pools are built once and
substitution is consistent across the whole run.
"""
from presidio_anonymizer.operators import Operator, OperatorType


class KeyedSubstitute(Operator):
    def operator_name(self) -> str:
        return "keyed_substitute"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize

    def validate(self, params) -> None:
        if params is None or "substitutor" not in params:
            raise ValueError("keyed_substitute requires a 'substitutor' param")

    def operate(self, text, params=None) -> str:
        params = params or {}
        sub = params["substitutor"]
        entity_type = params.get("entity_type", "")
        return sub.substitute_entity(entity_type, text)


_REGISTERED = False


def register_operators():
    """Register custom operators so every freshly-constructed OperatorsFactory
    sees them. The factory loads from the module-level ANONYMIZERS list on each
    construction (the structured data processor builds a fresh factory per call),
    so registration appends there rather than to an engine instance. Idempotent."""
    global _REGISTERED
    if _REGISTERED:
        return
    from presidio_anonymizer.operators import operators_factory as _of
    if KeyedSubstitute not in _of.ANONYMIZERS:
        _of.ANONYMIZERS.append(KeyedSubstitute)
    _REGISTERED = True
