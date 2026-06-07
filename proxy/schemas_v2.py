"""v2 abstraction manifest. The signed manifest binds the full abstraction context
so a verifier knows exactly what was done: source format, locale, the content-based
detection mapping, which operator hit each entity, the reversibility mode, and the
gate result including whether re-id risk was actually assessed. cert.py signs every
field except the signature pair, so adding fields here strengthens the binding."""
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field


class AbstractionManifestV2(BaseModel):
    schema_version: int = 2
    doc_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    records: int = 0
    source_format: str = "dataframe"        # csv|json|excel|parquet|sql|image|dataframe
    language: str = "en"
    policy: str = "content-based"
    detection: dict[str, str] = Field(default_factory=dict)   # column -> entity
    kept_columns: list[str] = Field(default_factory=list)     # QI/signal pass-through
    operators: dict[str, str] = Field(default_factory=dict)   # entity -> operator name
    reversibility: str = "oneway"           # oneway|map|encrypt
    gate: dict | None = None                # full gate result incl. assessed/trivial_pass
    before_hash: str = ""
    after_hash: str = ""
    signature: str = ""
    signer_pubkey: str = ""
