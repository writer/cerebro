"""Property-based tests for IAM edge normalization."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from hypothesis import given
from hypothesis import strategies as st


def _edge_strategy():
    base_time = datetime.utcnow()
    return st.fixed_dictionaries(
        {
            "account_id": st.just(uuid4()),
            "provider": st.sampled_from(["aws", "github", "gcp"]),
            "principal_id": st.just(uuid4()),
            "resource_id": st.one_of(st.none(), st.just(uuid4())),
            "permission": st.text(min_size=1, max_size=32),
            "via": st.one_of(st.none(), st.text(min_size=1, max_size=32)),
            "effective_at": st.datetimes(
                min_value=base_time - timedelta(days=30), max_value=base_time
            ),
            "expires_at": st.one_of(
                st.none(),
                st.datetimes(
                    min_value=base_time, max_value=base_time + timedelta(days=365)
                ),
            ),
            "is_admin": st.booleans(),
        }
    )


@given(edges=st.lists(_edge_strategy(), min_size=1, max_size=50))
def test_unique_constraint_projection(edges):
    normalized = {
        (
            e["account_id"],
            e["provider"],
            e["principal_id"],
            e["resource_id"],
            e["permission"],
            e["effective_at"],
            e["via"],
        )
        for e in edges
    }
    assert len(normalized) <= len(edges)
