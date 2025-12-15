from __future__ import annotations

import pytest

from cerebro.query.engine import SQLParser
from cerebro.query.registry import get_registry
from cerebro.query.table import SecurityTable


class _DummyTable(SecurityTable):
    async def list_resources(self, ctx):  # pragma: no cover
        if False:
            yield {}


def test_wildcard_expansion_is_capped(monkeypatch):
    monkeypatch.setenv("QUERY_ENGINE_MAX_WILDCARD_TABLES", "5")

    registry = get_registry()
    created = []
    try:
        for i in range(10):
            name = f"dummy_guard_{i}"
            registry.register_table(_DummyTable(name=name, description="dummy"))
            created.append(name)

        parser = SQLParser()
        with pytest.raises(ValueError) as exc:
            parser.parse_query("SELECT * FROM dummy_guard_*")
        assert "QUERY_ENGINE_MAX_WILDCARD_TABLES" in str(exc.value)
    finally:
        for name in created:
            registry.unregister_table(name)


def test_or_filters_are_rejected():
    parser = SQLParser()
    with pytest.raises(ValueError) as exc:
        parser.parse_query("SELECT * FROM some_table WHERE a = 1 OR b = 2")
    assert "OR conditions are not supported" in str(exc.value)
