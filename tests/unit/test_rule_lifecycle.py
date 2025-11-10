"""Unit tests for rule lifecycle helpers."""

from __future__ import annotations

import pytest

from cerebro.rules.engine import rule_engine
from cerebro.rules.exceptions import CompilationError


def test_compile_rule_handles_invalid_expression() -> None:
    with pytest.raises(CompilationError):
        rule_engine.compile_rule("resource.provider == ")
