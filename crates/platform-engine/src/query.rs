//! Resource-bounded execution planning for validated graph fact queries.
//!
//! This module classifies a [`FactQuery`] by the least expansive access shape
//! implied by its bindings. It does not compile backend syntax or execute a
//! read; adapters remain responsible for honoring every limit copied into the
//! resulting [`QueryExecutionPlan`].

use cerebro_platform_sdk::{FactQuery, ResourceBudget, SdkError};
use serde::Serialize;

/// Storage-neutral access shape selected for a validated fact query.
///
/// The variants are planning signals, not authorization or completeness
/// claims. A backend must still enforce tenant scope, query predicates, result
/// limits, and the deadline carried by [`QueryExecutionPlan`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStrategy {
    /// Resolve a query for which every node has at least one stable key.
    ///
    /// This remains the preferred strategy when keyed nodes are also connected
    /// by edges: resolving the bounded candidate set precedes checking those
    /// relationships.
    StableKeyLookup,
    /// Traverse one or more required edges because some node is not key-bound.
    BoundedTraversal,
    /// Scan a bounded projection for an edge-free, non-keyed node query.
    BoundedProjectionScan,
}

/// Hard execution limits and access strategy for one graph fact query.
///
/// The plan is derived entirely from an already validated [`FactQuery`] and a
/// caller-supplied [`ResourceBudget`]. It contains no tenant credentials,
/// backend query text, or mutable progress state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryExecutionPlan {
    /// Access shape the backend should use to satisfy the query.
    pub strategy: QueryStrategy,
    /// Maximum rows the backend may return, copied from the query limit.
    pub max_rows: u32,
    /// Number of required query edges, bounded by the tenant query budget.
    ///
    /// Negative edge checks constrain completed bindings and therefore do not
    /// contribute to this positive traversal depth.
    pub max_depth: u8,
    /// Wall-clock execution deadline imposed by the resource budget.
    pub deadline_millis: u32,
}

/// Produces a storage-neutral execution plan within the supplied resource budget.
///
/// Strategy selection is intentionally ordered: a fully key-bound query uses
/// [`QueryStrategy::StableKeyLookup`] even when it includes required edges; an
/// unkeyed query with required edges uses bounded traversal; only an edge-free,
/// unkeyed query uses a bounded projection scan. The function does not execute
/// the query and does not weaken the structural bounds established by
/// [`FactQuery`].
///
/// # Errors
///
/// Returns [`SdkError::OutOfRange`] when the requested result count or required
/// edge count cannot be represented by the plan, or when either exceeds its
/// corresponding [`ResourceBudget`] limit.
pub fn plan_query(
    query: &FactQuery,
    budget: &ResourceBudget,
) -> Result<QueryExecutionPlan, SdkError> {
    // Convert before comparing so every serialized plan uses the fixed-width
    // wire representation promised by `QueryExecutionPlan`.
    let requested_rows =
        u32::try_from(query.limit()).map_err(|_| SdkError::OutOfRange("query result limit"))?;
    if requested_rows > budget.max_query_results {
        return Err(SdkError::OutOfRange("query result limit"));
    }
    let depth =
        u8::try_from(query.edges().len()).map_err(|_| SdkError::OutOfRange("query depth"))?;
    if depth > budget.max_query_depth {
        return Err(SdkError::OutOfRange("query depth"));
    }

    // Fully bound nodes produce a finite candidate set even when the query
    // subsequently checks relationships between those candidates.
    let has_stable_keys = query.nodes().iter().all(|node| !node.keys.is_empty());
    let strategy = if has_stable_keys {
        QueryStrategy::StableKeyLookup
    } else if !query.edges().is_empty() {
        QueryStrategy::BoundedTraversal
    } else {
        QueryStrategy::BoundedProjectionScan
    };
    Ok(QueryExecutionPlan {
        strategy,
        max_rows: requested_rows,
        max_depth: depth,
        deadline_millis: budget.max_query_millis,
    })
}

#[cfg(test)]
mod tests {
    use cerebro_platform_sdk::{QueryEdge, QueryNode};

    use super::*;

    #[test]
    fn planner_rejects_a_positive_query_deeper_than_the_tenant_budget() {
        let query = FactQuery::new(
            vec![
                QueryNode {
                    variable: "repository".to_owned(),
                    kinds: vec!["repository".to_owned()],
                    keys: Vec::new(),
                },
                QueryNode {
                    variable: "service".to_owned(),
                    kinds: vec!["service".to_owned()],
                    keys: Vec::new(),
                },
                QueryNode {
                    variable: "environment".to_owned(),
                    kinds: vec!["environment".to_owned()],
                    keys: Vec::new(),
                },
            ],
            vec![
                QueryEdge {
                    variable: "build".to_owned(),
                    from_variable: "repository".to_owned(),
                    relation: "builds".to_owned(),
                    to_variable: "service".to_owned(),
                },
                QueryEdge {
                    variable: "runtime".to_owned(),
                    from_variable: "service".to_owned(),
                    relation: "runs_in".to_owned(),
                    to_variable: "environment".to_owned(),
                },
            ],
            Vec::new(),
            10,
        )
        .unwrap();
        let budget = ResourceBudget::new(10, 1, 100, 1, 1, 10, 1_024, 100).expect("valid budget");

        assert_eq!(
            plan_query(&query, &budget),
            Err(SdkError::OutOfRange("query depth"))
        );
    }
}
