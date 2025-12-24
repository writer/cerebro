"""Lightweight timestamping stubs used in tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class TimestampToken:
    payload_hash: str
    timestamp: datetime
    metadata: dict[str, Any]


class TimestampService:
    """Minimal timestamp service placeholder."""

    async def timestamp(
        self, payload: bytes, **metadata: Any
    ) -> TimestampToken:  # pragma: no cover - simple utility
        return TimestampToken(
            payload_hash=payload.hex() if isinstance(payload, bytes) else str(payload),
            timestamp=datetime.utcnow(),
            metadata=metadata,
        )


class RFC3161Timestamper(TimestampService):
    """Compatibility shim representing RFC-3161 timestamping."""

    async def timestamp(
        self, payload: bytes, **metadata: Any
    ) -> TimestampToken:  # pragma: no cover
        metadata = {"rfc3161": True, **metadata}
        return await super().timestamp(payload, **metadata)


_DEFAULT_SERVICE: TimestampService | None = None


def get_timestamp_service() -> TimestampService:
    """Return a shared timestamp service instance."""

    global _DEFAULT_SERVICE
    if _DEFAULT_SERVICE is None:
        _DEFAULT_SERVICE = RFC3161Timestamper()
    return _DEFAULT_SERVICE
