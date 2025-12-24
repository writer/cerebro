"""Configuration helpers for the Cerebro SDK.

This module provides a light-weight facade over :mod:`cerebro.core.config`
allowing internal tooling to hydrate settings with sensible caching semantics.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from cerebro.core.config import Settings

_lock = threading.RLock()
_settings: Settings | None = None


def _ensure_settings(loader: Callable[[], Settings]) -> Settings:
    global _settings
    if _settings is None:
        _settings = loader()
    return _settings


def get_settings(loader: Callable[[], Settings] = Settings) -> Settings:
    """Return a cached settings instance."""

    with _lock:
        return _ensure_settings(loader)


def refresh_settings(factory: Callable[[], Settings] | None = None) -> Settings:
    """Refresh and return the cached settings instance."""

    global _settings
    with _lock:
        loader = factory or Settings
        _settings = loader()
        return _settings


class SettingsProxy:
    """Thin proxy exposing attribute access to the cached settings."""

    __slots__ = ("_loader",)

    def __init__(self, loader: Callable[[], Settings] = get_settings) -> None:
        self._loader = loader

    def __getattr__(self, item: str):
        return getattr(self._loader(), item)

    def snapshot(self) -> Settings:
        """Return the underlying settings object."""

        return self._loader()
