from datetime import datetime
from typing import List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class COMObject(BaseModel):
    """Base class for all Common OSINT Model objects (EXT-05).

    Provides normalized fields for identity, timestamps, provenance,
    classification, and tagging across all COM types. Every concrete
    COM class inherits from COMObject so that cross-type feature
    matrices are consistent and every object carries a stable UUID
    that can be referenced by the Relation model (EXT-01).
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    sources: List[str] = Field(default_factory=list)
    classification: Literal["malicious", "suspicious", "benign", "unknown"] = "unknown"
    tags: List[str] = Field(default_factory=list)
