from __future__ import annotations

from cerebro.analytics.sql_dialect import array_has_elements_expr, array_length_expr


def test_array_length_expr_returns_dialect_specific_length() -> None:
    assert (
        array_length_expr(column_expr="r.cis", dialect="snowflake")
        == "ARRAY_SIZE(r.cis)"
    )
    assert (
        array_length_expr(column_expr="r.cis", dialect="sqlite")
        == "json_array_length(r.cis)"
    )
    assert (
        array_length_expr(column_expr="r.cis", dialect="postgresql")
        == "CARDINALITY(r.cis)"
    )


def test_array_has_elements_expr_wraps_with_coalesce_predicate() -> None:
    assert (
        array_has_elements_expr(column_expr="r.cis", dialect="snowflake")
        == "(COALESCE(ARRAY_SIZE(r.cis), 0) > 0)"
    )
    assert (
        array_has_elements_expr(column_expr="r.cis", dialect="sqlite")
        == "(COALESCE(json_array_length(r.cis), 0) > 0)"
    )
    assert (
        array_has_elements_expr(column_expr="r.cis", dialect="postgresql")
        == "(COALESCE(CARDINALITY(r.cis), 0) > 0)"
    )
