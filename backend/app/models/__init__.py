"""ORM model registration for implemented domain tables."""

from app.models.intelligence_item import IntelligenceItem
from app.models.intelligence_item_identifier import IntelligenceItemIdentifier
from app.models.intelligence_item_tag import IntelligenceItemTag
from app.models.intelligence_source import IntelligenceSource
from app.models.source_record import SourceRecord
from app.models.tag import Tag
from app.models.vulnerability import Vulnerability

__all__ = [
    "IntelligenceItem",
    "IntelligenceItemIdentifier",
    "IntelligenceItemTag",
    "IntelligenceSource",
    "SourceRecord",
    "Tag",
    "Vulnerability",
]
