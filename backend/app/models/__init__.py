"""ORM model registration for implemented domain tables."""

from app.models.ingestion_error import IngestionError
from app.models.ingestion_run import IngestionRun
from app.models.ingestion_run_record import IngestionRunRecord
from app.models.indicator import Indicator
from app.models.indicator_provenance import IndicatorProvenance
from app.models.intelligence_item import IntelligenceItem
from app.models.intelligence_item_identifier import IntelligenceItemIdentifier
from app.models.intelligence_item_tag import IntelligenceItemTag
from app.models.intelligence_source import IntelligenceSource
from app.models.source_record import SourceRecord
from app.models.tag import Tag
from app.models.vulnerability import Vulnerability

__all__ = [
    "IngestionError",
    "IngestionRun",
    "IngestionRunRecord",
    "Indicator",
    "IndicatorProvenance",
    "IntelligenceItem",
    "IntelligenceItemIdentifier",
    "IntelligenceItemTag",
    "IntelligenceSource",
    "SourceRecord",
    "Tag",
    "Vulnerability",
]
