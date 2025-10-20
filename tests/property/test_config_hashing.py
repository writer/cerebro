"""Property-based tests for configuration hashing."""

from __future__ import annotations

import json
from uuid import uuid4

from hypothesis import given, strategies as st

from cerebro.core.bulk_operations import compute_config_hash


config_strategy = st.recursive(
    st.none() | st.booleans() | st.floats(allow_nan=False) | st.text() | st.integers(),
    lambda children: st.dictionaries(st.text(), children, max_size=5)
    | st.lists(children, max_size=5),
    max_leaves=50,
)


@given(config=config_strategy)
def test_compute_hash_is_deterministic(config):
    assert compute_config_hash(config) == compute_config_hash(config)


@given(config=config_strategy)
def test_hash_changes_with_modification(config):
    original_hash = compute_config_hash(config)
    modified = config
    if isinstance(config, dict):
        modified = {**config, "__extra": str(uuid4())}
    elif isinstance(config, list):
        modified = list(config) + [str(uuid4())]
    elif isinstance(config, (str, int, float, type(None), bool)):
        modified = [config, str(uuid4())]

    assert compute_config_hash(modified) != original_hash
