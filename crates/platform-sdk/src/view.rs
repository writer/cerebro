//! Materialized-query view definitions and refresh receipts.
//!
//! A view couples a bounded fact query to a stable tenant-scoped identity. The
//! SDK validates definition shape; query execution, scheduling, persistence,
//! and access control belong to the runtime implementing the view service.

use serde::Serialize;

use crate::{ContentDigest, FactQuery, GraphRevision, SdkError, TenantId, ViewId};

/// Lifecycle state reported for a materialized view snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewRefreshState {
    /// Snapshot reflects the last successful refresh known to the service.
    Current,
    /// A refresh has been requested but has not started.
    Pending,
    /// A refresh is actively rebuilding the snapshot.
    Rebuilding,
    /// The most recent refresh attempt failed.
    Failed,
}

/// Validated definition of one tenant-scoped materialized fact query.
///
/// The caller-supplied definition digest is not recomputed by [`Self::validate`].
/// The definition assembly boundary must canonically bind the identity, tenant,
/// name, query, and row ceiling before persisting the definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MaterializedViewDefinition {
    /// Stable identity of the materialized view.
    pub view_id: ViewId,
    /// Tenant whose graph may satisfy the query.
    pub tenant_id: TenantId,
    /// Non-empty display name preserved exactly as supplied.
    pub name: String,
    /// Bounded fact query executed during refresh.
    pub query: FactQuery,
    /// Hard materialization ceiling in the inclusive range `1..=500`.
    pub max_rows: u32,
    /// Caller-supplied digest of the canonical definition.
    pub definition_digest: ContentDigest,
}

impl MaterializedViewDefinition {
    /// Validates the name and row ceiling against the query limit.
    ///
    /// Names may contain internal whitespace but cannot have surrounding
    /// whitespace and cannot exceed 256 bytes. `max_rows` must be no greater
    /// than both 500 and the query's own limit.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Invalid`] for an empty or padded name,
    /// [`SdkError::TooLong`] for a name over 256 bytes, or
    /// [`SdkError::OutOfRange`] for an invalid row ceiling.
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

/// Receipt describing one materialized view refresh.
///
/// The snapshot contains metadata and a digest, not the materialized rows. A
/// `Current` receipt reports successful assembly; other lifecycle states are
/// produced by the surrounding refresh service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MaterializedViewSnapshot {
    /// View whose result was refreshed.
    pub view_id: ViewId,
    /// Tenant whose graph produced the result.
    pub tenant_id: TenantId,
    /// Non-zero graph revision read by the query.
    pub graph_revision: GraphRevision,
    /// Number of rows in the complete materialized result.
    pub row_count: u32,
    /// Refresh lifecycle state.
    pub state: ViewRefreshState,
    /// Caller-supplied Unix-millisecond completion time.
    pub refreshed_at_unix_millis: i64,
    /// Digest binding the view identity and definition digest to the query result.
    pub result_digest: ContentDigest,
}
