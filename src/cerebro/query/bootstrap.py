"""Query engine bootstrap utilities.

Provides helpers to ensure the global table registry is initialized once and
to supply shared query engine instances without forcing each caller to manage
provider table registration directly.
"""

from __future__ import annotations

import threading
from typing import Optional

from .registry import TableRegistry, get_registry
from ..providers.tables import register_all_provider_tables

_bootstrap_lock = threading.RLock()
_tables_registered = False


def ensure_tables_registered(
    *, registry: Optional[TableRegistry] = None, force: bool = False
) -> TableRegistry:
    """Ensure provider tables are registered on the target registry."""

    global _tables_registered

    target_registry = registry or get_registry()

    # Only bootstrap the global registry – custom registries are assumed to be
    # managed by the caller (used extensively in tests).
    if registry is not None and registry is not get_registry():
        return target_registry

    with _bootstrap_lock:
        if force or not _tables_registered:
            register_all_provider_tables()
            _tables_registered = True

    return target_registry


def get_query_engine(
    *,
    registry: Optional[TableRegistry] = None,
    force_refresh: bool = False,
    shared: bool = True,
):
    """Return a query engine with provider tables registered."""

    from .engine import QueryEngine  # Local import to avoid circular dependency

    if registry is not None and registry is not get_registry():
        # Custom registries should not reuse the shared instance.
        ensure_tables_registered(registry=registry, force=force_refresh)
        return QueryEngine(registry=registry)

    if not shared:
        ensure_tables_registered(force=force_refresh)
        return QueryEngine()

    with _bootstrap_lock:
        if force_refresh or not hasattr(get_query_engine, "_shared_engine"):
            ensure_tables_registered(force=True if force_refresh else False)
            get_query_engine._shared_engine = QueryEngine()
        return get_query_engine._shared_engine


def reset_query_engine_cache() -> None:
    """Clear the cached shared query engine (useful for tests)."""

    with _bootstrap_lock:
        if hasattr(get_query_engine, "_shared_engine"):
            delattr(get_query_engine, "_shared_engine")
