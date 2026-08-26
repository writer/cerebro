use cerebro_platform_sdk::{
    GraphRevision, MaterializedViewDefinition, MaterializedViewSnapshot, QueryResult, SdkError,
    ViewRefreshState,
};

use crate::canonical;

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
        result_digest: canonical::digest(&(
            &definition.view_id,
            &definition.definition_digest,
            result,
        ))?,
    })
}

#[cfg(test)]
mod tests {
    use cerebro_platform_sdk::{FactQuery, QueryNode, ViewId};

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
