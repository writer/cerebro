"""Compatibility layer for legacy ``cerebro.rules.models`` imports."""

from cerebro.core.models import Rule as _CoreRule

Rule = _CoreRule

__all__ = ["Rule"]
