from proxy.schemas import Span, SemanticClass, Substitution, EntityMapEntry, AbstractionManifest


def test_span_roundtrip():
    s = Span(text="John", start=0, end=4, entity_type="PERSON", score=0.9)
    assert Span.model_validate_json(s.model_dump_json()) == s


def test_semantic_class_is_inspectable():
    sc = SemanticClass(field="State", entity_type="LOCATION", attributes={"region": "Northeast"})
    assert isinstance(sc.attributes, dict)
    assert sc.attributes["region"] == "Northeast"
    assert SemanticClass.model_validate_json(sc.model_dump_json()) == sc


def test_substitution_format_only_has_no_class():
    sub = Substitution(replacement="(555) 010-1234", entity_type="PHONE", field="Phone Number")
    assert sub.semantic_class is None
    assert Substitution.model_validate_json(sub.model_dump_json()) == sub


def test_entity_map_entry_roundtrip():
    e = EntityMapEntry(entity_key="SH-1", original="John", replacement="Mark")
    assert EntityMapEntry.model_validate_json(e.model_dump_json()) == e


def test_manifest_defaults_and_roundtrip():
    m = AbstractionManifest(records=500, fields_abstracted=["First Name"], before_hash="a", after_hash="b")
    r = AbstractionManifest.model_validate_json(m.model_dump_json())
    assert r.doc_id == m.doc_id
    assert r.records == 500
