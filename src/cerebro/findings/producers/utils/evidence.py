"""Utility helpers for normalizing evidence payloads."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from itertools import islice
from typing import Any


def clip_sequence(values: Iterable[Any] | None, limit: int = 10) -> list[Any]:
    """Return at most ``limit`` items from ``values`` as a list."""

    if not values or limit <= 0:
        return []

    if isinstance(values, Sequence):
        return list(values[: limit])  # type: ignore[index]

    return list(islice(values, limit))


def compact_mapping(mapping: Mapping[str, Any] | None) -> dict[str, Any]:
    """Remove keys with ``None`` values from a mapping."""

    if not mapping:
        return {}

    return {key: value for key, value in mapping.items() if value is not None}
