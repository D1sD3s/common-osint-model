from typing import Literal

from pydantic import Field

from common_osint_model.models.com_object import COMObject

RelationType = Literal[
    "shares-cert",        # two hosts share a certificate
    "communicates-with",  # one host sends traffic to another host (e.g. C2 channel)
    "drops",              # host drops a file to another host
    "resolves-to",        # domain resolves to a host IP
    "hosted-in",          # IP is hosted within specific ASN / Network range
    "contains",           # inverse of hosted-in
]


class Relation(COMObject):
    """Directed relationship between two COM objects"""

    source_ref: str
    target_ref: str
    relation_type: RelationType
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
