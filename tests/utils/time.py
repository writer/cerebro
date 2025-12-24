"""Timezone-aware datetime helpers for tests."""

from datetime import UTC, datetime

UTC = UTC


def utc_now() -> datetime:
    """Return the current UTC datetime."""

    return datetime.now(UTC)


__all__ = ["UTC", "utc_now"]
