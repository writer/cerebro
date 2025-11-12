"""Helper functions for safely coercing normalized configuration data."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def coerce_mapping(value: Any) -> Mapping[str, Any] | None:
    """Return the mapping if the value is mapping-like."""

    return value if isinstance(value, Mapping) else None


def coerce_mapping_sequence(value: Any) -> tuple[Mapping[str, Any], ...]:
    """Return a tuple of mappings from a sequence, dropping invalid entries."""

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        entries: list[Mapping[str, Any]] = []
        for entry in value:
            if isinstance(entry, Mapping):
                entries.append(entry)
        return tuple(entries)
    if isinstance(value, Mapping):
        return (value,)
    return ()


def coerce_str_sequence(value: Any) -> tuple[str, ...]:
    """Normalize the input into a tuple of non-empty strings."""

    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(item for item in value if isinstance(item, str) and item)
    return ()
