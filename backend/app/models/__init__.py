"""ORM model registration for implemented domain tables."""

from app.models.audit_event import AuditEvent
from app.models.auth_identity import AuthIdentity, AuthLocalCredential
from app.models.auth_role import AuthUserRole
from app.models.auth_session import AuthLoginThrottle, AuthSession
from app.models.auth_user import AuthUser
from app.models.ingestion_cycle import IngestionCycle

from app.models.ingestion_error import IngestionError
from app.models.ingestion_run import IngestionRun
from app.models.ingestion_run_event import IngestionRunEvent
from app.models.ingestion_run_record import IngestionRunRecord
from app.models.indicator import Indicator
from app.models.indicator_provenance import IndicatorProvenance
from app.models.intelligence_item import IntelligenceItem
from app.models.intelligence_item_identifier import IntelligenceItemIdentifier
from app.models.intelligence_item_indicator import IntelligenceItemIndicator
from app.models.intelligence_item_tag import IntelligenceItemTag
from app.models.intelligence_source import IntelligenceSource
from app.models.quarantined_record import QuarantinedRecord
from app.models.source_checkpoint import SourceCheckpoint
from app.models.source_credential_reference import SourceCredentialReference
from app.models.source_rate_limit_state import SourceRateLimitState
from app.models.source_record import SourceRecord
from app.models.source_watermark import SourceWatermark
from app.models.tag import Tag
from app.models.threat_entity import ThreatEntity
from app.models.threat_entity_alias import ThreatEntityAlias
from app.models.threat_relationship import ThreatRelationship
from app.models.vulnerability import Vulnerability

__all__ = [
    "AuditEvent",
    "AuthIdentity",
    "AuthLocalCredential",
    "AuthLoginThrottle",
    "AuthSession",
    "AuthUser",
    "AuthUserRole",
    "IngestionError",
    "IngestionCycle",
    "IngestionRun",
    "IngestionRunEvent",
    "IngestionRunRecord",
    "Indicator",
    "IndicatorProvenance",
    "IntelligenceItem",
    "IntelligenceItemIdentifier",
    "IntelligenceItemIndicator",
    "IntelligenceItemTag",
    "IntelligenceSource",
    "QuarantinedRecord",
    "SourceCheckpoint",
    "SourceCredentialReference",
    "SourceRateLimitState",
    "SourceRecord",
    "SourceWatermark",
    "Tag",
    "ThreatEntity",
    "ThreatEntityAlias",
    "ThreatRelationship",
    "Vulnerability",
]
