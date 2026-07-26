use cerebro_platform_sdk::{FactQuery, ResourceBudget, SdkError};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStrategy {
    StableKeyLookup,
    BoundedTraversal,
    BoundedProjectionScan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryExecutionPlan {
    pub strategy: QueryStrategy,
    pub max_rows: u32,
    pub max_depth: u8,
    pub deadline_millis: u32,
}

pub fn plan_query(
    query: &FactQuery,
    budget: &ResourceBudget,
) -> Result<QueryExecutionPlan, SdkError> {
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
