"""Cursor-based pagination utilities for Cerebro SDK facades."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Generic, Optional, Sequence, TypeVar


T = TypeVar("T")


@dataclass
class PageRequest:
    """Pagination request parameters passed to list operations."""

    limit: int = 100
    cursor: Optional[str] = None


@dataclass(frozen=True)
class Cursor:
    """Parsed cursor payload supporting strongly typed lookups."""

    raw: str
    payload: dict[str, object]

    def get(self, key: str, default: object | None = None) -> object | None:
        return self.payload.get(key, default)


@dataclass
class CursorPage(Generic[T]):
    """Generic cursor page representation returned by SDK helpers."""

    items: Sequence[T]
    next_cursor: Optional[str]
    total: Optional[int] = None


def encode_cursor(payload: dict[str, object]) -> str:
    """Encode a cursor payload into a URL-safe base64 token."""

    serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    token = base64.urlsafe_b64encode(serialized.encode("utf-8")).decode("ascii")
    return token.rstrip("=")


def decode_cursor(token: str) -> Cursor:
    """Decode a cursor token into a structured payload."""

    padding = "=" * (-len(token) % 4)
    raw = token + padding
    data = base64.urlsafe_b64decode(raw.encode("ascii")).decode("utf-8")
    payload = json.loads(data)
    if not isinstance(payload, dict):
        raise ValueError("Cursor payload must decode to a mapping")
    return Cursor(raw=token, payload=payload)


__all__ = [
    "PageRequest",
    "Cursor",
    "CursorPage",
    "encode_cursor",
    "decode_cursor",
]
