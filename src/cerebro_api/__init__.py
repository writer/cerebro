"""Compatibility shims for legacy cerebro_api import paths."""

from cerebro.api.schemas.main import (  # noqa: F401
    FindingPageResponse,
    FindingResponse,
    FindingStats,
    FindingUpdate,
)

__all__ = [
    "FindingResponse",
    "FindingUpdate",
    "FindingStats",
    "FindingPageResponse",
]
