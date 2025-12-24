"""Compatibility models for findings status/severity enumerations.

This module preserves the legacy import path ``cerebro.findings.models`` which
historically exposed the ``FindingStatus`` and ``Severity`` enums used
throughout tests and tooling. The canonical definitions now live in
``cerebro.domain.entities``; we simply alias them here to avoid duplicating
logic and ensure a single source of truth.
"""

from cerebro.domain.entities import FindingStatus as _DomainFindingStatus
from cerebro.domain.entities import Severity as _DomainSeverity

FindingStatus = _DomainFindingStatus
Severity = _DomainSeverity


__all__ = ["FindingStatus", "Severity"]
