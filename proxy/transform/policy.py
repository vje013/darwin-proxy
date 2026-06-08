"""Per-entity operator policy. Identifiers are pseudonymized with the keyed
operator (signal-preserving, join-stable). Quasi-identifiers the re-id gate needs
(geography, dates) are KEPT by excluding them from the transform mapping so they
pass through untouched. Unknown detected entities fall to the keyed operator,
because over-pseudonymizing is the safe failure mode, not leaking.
"""
from presidio_anonymizer import OperatorConfig

# Left for the gate to generalize/suppress; never substituted.
KEEP_ENTITIES = {"LOCATION", "GPE", "DATE_TIME", "NRP_LOCATION"}


def split_mapping(mapping):
    """Return (to_transform, kept). kept entities pass through untouched."""
    to_transform, kept = {}, {}
    for col, ent in mapping.items():
        (kept if ent in KEEP_ENTITIES else to_transform)[col] = ent
    return to_transform, kept


def build_operators(entities, substitutor):
    """Map each entity to a keyed_substitute OperatorConfig carrying its
    entity_type (the structured path does not inject it) and the shared
    substitutor. Includes a DEFAULT so any unforeseen entity is still pseudonymized."""
    ops = {ent: OperatorConfig("keyed_substitute",
                               {"entity_type": ent, "substitutor": substitutor})
           for ent in set(entities)}
    ops["DEFAULT"] = OperatorConfig("keyed_substitute",
                                    {"entity_type": "", "substitutor": substitutor})
    return ops
