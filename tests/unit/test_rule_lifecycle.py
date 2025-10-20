"""Unit tests for rule lifecycle helpers."""

from __future__ import annotations

import pytest

from cerebro.rules.engine import rule_engine


def test_compile_rule_handles_invalid_expression() -> None:
    with pytest.raises(Exception):
        rule_engine.compile_rule("resource.provider == ")
