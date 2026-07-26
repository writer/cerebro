use serde::Serialize;

use crate::{ContentDigest, FactQuery, GraphRevision, SdkError, TenantId, ViewId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewRefreshState {
    Current,
    Pending,
    Rebuilding,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MaterializedViewDefinition {
    pub view_id: ViewId,
    pub tenant_id: TenantId,
    pub name: String,
    pub query: FactQuery,
    pub max_rows: u32,
    pub definition_digest: ContentDigest,
}

impl MaterializedViewDefinition {
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.name.trim() != self.name || self.name.is_empty() {
            return Err(SdkError::Invalid("materialized view name"));
        }
        if self.name.len() > 256 {
            return Err(SdkError::TooLong("materialized view name"));
        }
        if self.max_rows == 0 || self.max_rows > 500 || self.max_rows as usize > self.query.limit()
        {
            return Err(SdkError::OutOfRange("materialized view max rows"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MaterializedViewSnapshot {
    pub view_id: ViewId,
    pub tenant_id: TenantId,
    pub graph_revision: GraphRevision,
    pub row_count: u32,
    pub state: ViewRefreshState,
    pub refreshed_at_unix_millis: i64,
    pub result_digest: ContentDigest,
}
