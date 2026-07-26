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
        result_digest: canonical::digest(result)?,
    })
}
