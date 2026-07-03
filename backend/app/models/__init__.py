"""ORM model registration for implemented domain tables."""

from app.models.intelligence_item import IntelligenceItem
from app.models.intelligence_source import IntelligenceSource

__all__ = ["IntelligenceItem", "IntelligenceSource"]
