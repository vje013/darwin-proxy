"""Darwin Proxy core schemas. SemanticClass is the keystone."""
from datetime import datetime, timezone
from uuid import uuid4
from pydantic import BaseModel, Field


class Span(BaseModel):
    text: str = ""
    start: int = 0
    end: int = 0
    entity_type: str
    score: float = 1.0


class SemanticClass(BaseModel):
    field: str
    entity_type: str
    attributes: dict = Field(default_factory=dict)
    radius: float = 1.0


class Substitution(BaseModel):
    replacement: str
    entity_type: str
    field: str
    semantic_class: SemanticClass | None = None


class EntityMapEntry(BaseModel):
    entity_key: str
    original: str
    replacement: str
    semantic_class: SemanticClass | None = None


class AbstractionManifest(BaseModel):
    doc_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    policy: str = "default"
    records: int = 0
    fields_abstracted: list[str] = Field(default_factory=list)
    fields_preserved: list[str] = Field(default_factory=list)
    semantic_classes: list[SemanticClass] = Field(default_factory=list)
    gate_result: dict | None = None
    before_hash: str = ""
    after_hash: str = ""
    signature: str = ""
    signer_pubkey: str = ""
