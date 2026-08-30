//! Assembly of successful materialized-view refresh receipts.
//!
//! This module validates and binds an already-computed query result. It does not
//! execute the view query, schedule refreshes, persist rows or receipts, or
//! authenticate access to the tenant graph.

use cerebro_platform_sdk::{
    GraphRevision, MaterializedViewDefinition, MaterializedViewSnapshot, QueryResult, SdkError,
    ViewRefreshState,
};

use crate::canonical;

/// Validates a complete query result and produces a `Current` refresh receipt.
///
/// The result must belong to the definition tenant, must not be truncated, and
/// must fit the definition's row ceiling. This function does not prove that the
/// result was produced by `definition.query`; the query execution boundary must
/// carry that binding into this call.
///
/// The receipt digest covers the view identity, caller-supplied definition
/// digest, and complete query result. It intentionally excludes refresh time and
/// lifecycle state, so operational timing does not change content identity.
///
/// # Errors
///
/// Returns definition validation errors, [`SdkError::Invalid`] for a result from
/// another tenant, [`SdkError::OutOfRange`] for a truncated or oversized result,
/// zero graph revision, or unrepresentable row count, and [`SdkError::Backend`]
/// if canonical serialization fails.
pub fn materialize_view(
    definition: &MaterializedViewDefinition,
    result: &QueryResult,
    refreshed_at_unix_millis: i64,
) -> Result<MaterializedViewSnapshot, SdkError> {
    definition.validate()?;
    if definition.tenant_id != result.tenant_id {
        return Err(SdkError::Invalid("materialized view tenant"));
    }
    if result.truncated || result.matches.len() > definition.max_rows as usize {
        return Err(SdkError::OutOfRange("materialized view rows"));
    }

    // QueryResult uses a wire-level integer; the receipt tightens it to the
    // non-zero graph revision contract before publishing a successful state.
    let graph_revision = GraphRevision::new(result.graph_revision)?;
    let row_count = u32::try_from(result.matches.len())
        .map_err(|_| SdkError::OutOfRange("materialized view rows"))?;
    Ok(MaterializedViewSnapshot {
        view_id: definition.view_id.clone(),
        tenant_id: definition.tenant_id.clone(),
        graph_revision,
        row_count,
        state: ViewRefreshState::Current,
        refreshed_at_unix_millis,

        // The definition digest is trusted input here. Definition assembly must
        // recompute and verify it before this content binding is authoritative.
        result_digest: canonical::digest(&(
            &definition.view_id,
            &definition.definition_digest,
            result,
        ))?,
    })
}

#[cfg(test)]
mod tests {
    use cerebro_platform_sdk::{ContentDigest, FactQuery, QueryNode, TenantId, ViewId};

    use super::*;

    #[test]
    fn materialization_rejects_results_from_another_tenant() {
        let definition = MaterializedViewDefinition {
            view_id: ViewId::parse("view:test").unwrap(),
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            name: "Repositories".to_owned(),
            query: FactQuery::new(
                vec![QueryNode {
                    variable: "repository".to_owned(),
                    kinds: vec!["repository".to_owned()],
                    keys: Vec::new(),
                }],
                Vec::new(),
                Vec::new(),
                10,
            )
            .unwrap(),
            max_rows: 10,
            definition_digest: ContentDigest::of_bytes("definition"),
        };
        let result = QueryResult {
            tenant_id: TenantId::parse("tenant-b").unwrap(),
            graph_revision: 1,
            matches: Vec::new(),
            truncated: false,
        };

        assert_eq!(
            materialize_view(&definition, &result, 10),
            Err(SdkError::Invalid("materialized view tenant"))
        );
    }
}
