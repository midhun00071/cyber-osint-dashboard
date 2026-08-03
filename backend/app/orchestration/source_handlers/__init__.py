"""Immutable, inactive C02 source-handler bindings."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from app.orchestration.contracts import SourceHandler
from app.orchestration.source_handlers.cisa_kev import CisaKevSourceHandler
from app.orchestration.source_handlers.common import SessionFactory
from app.orchestration.source_handlers.epss import EpssSourceHandler
from app.orchestration.source_handlers.nvd import NvdSourceHandler
from app.orchestration.source_handlers.publications import (
    CERT_EU_SOURCE_SLUG,
    GOOGLE_SOURCE_SLUG,
    MANDIANT_SOURCE_SLUG,
    PublicationSourceHandler,
)


C02_BOUND_SOURCE_SLUGS = frozenset(
    {
        "cisa-kev",
        "nvd",
        "first-epss",
        CERT_EU_SOURCE_SLUG,
        GOOGLE_SOURCE_SLUG,
        MANDIANT_SOURCE_SLUG,
    }
)


def build_c02_source_handlers(
    *,
    session_factory: SessionFactory | None = None,
) -> Mapping[str, SourceHandler]:
    """Build reviewed-but-inactive handlers for tests and later controlled binding."""

    handlers: dict[str, SourceHandler] = {
        "cisa-kev": CisaKevSourceHandler(session_factory=session_factory),
        "nvd": NvdSourceHandler(session_factory=session_factory),
        "first-epss": EpssSourceHandler(session_factory=session_factory),
        CERT_EU_SOURCE_SLUG: PublicationSourceHandler(
            CERT_EU_SOURCE_SLUG,
            session_factory=session_factory,
        ),
        GOOGLE_SOURCE_SLUG: PublicationSourceHandler(
            GOOGLE_SOURCE_SLUG,
            session_factory=session_factory,
        ),
        MANDIANT_SOURCE_SLUG: PublicationSourceHandler(
            MANDIANT_SOURCE_SLUG,
            session_factory=session_factory,
        ),
    }
    if set(handlers) != C02_BOUND_SOURCE_SLUGS:
        raise RuntimeError("The C02 source-handler binding set is incomplete.")
    return MappingProxyType(handlers)


__all__ = ["C02_BOUND_SOURCE_SLUGS", "build_c02_source_handlers"]
