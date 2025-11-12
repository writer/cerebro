"""Shared helpers for resolving rule identifiers in producers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID


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
    context: Mapping[str, Any] | None,
) -> UUID:
    """Return a UUID for the rule associated with a producer evaluation."""

    rule_id = coerce_rule_id(context.get("rule_id")) if context else None
    if rule_id is not None:
        return rule_id

    from cerebro.rules.rule_service import get_rule_by_name_sync

    return get_rule_by_name_sync(rule_name)
