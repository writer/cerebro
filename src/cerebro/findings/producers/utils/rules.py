"""Shared helpers for resolving rule identifiers in producers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from .context import ProducerRunContext


def coerce_rule_id(value: object) -> UUID | None:
    """Convert a context-supplied value into a UUID when possible."""

    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        try:
            return UUID(value)
        except ValueError:
            return None
    return None


def resolve_rule_id(
    *,
    rule_name: str,
    context: ProducerRunContext | Mapping[str, Any] | None,
) -> UUID:
    """Return a UUID for the rule associated with a producer evaluation."""

    if context is not None:
        from .context import ProducerRunContext

        normalized = ProducerRunContext.ensure(context)
        if normalized and normalized.rule_id is not None:
            return normalized.rule_id

    from cerebro.rules.rule_service import get_rule_by_name_sync

    return get_rule_by_name_sync(rule_name)
