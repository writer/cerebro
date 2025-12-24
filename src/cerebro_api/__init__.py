"""Compatibility shims for legacy cerebro_api import paths."""

from cerebro.api.schemas.main import (
    FindingPageResponse,
    FindingResponse,
    FindingStats,
    FindingUpdate,
)

__all__ = [
    "FindingPageResponse",
    "FindingResponse",
    "FindingStats",
    "FindingUpdate",
]
