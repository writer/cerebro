"""Timezone-aware datetime helpers for tests."""

from datetime import datetime, timezone


UTC = timezone.utc


def utc_now() -> datetime:
    """Return the current UTC datetime."""

    return datetime.now(UTC)


__all__ = ["UTC", "utc_now"]
