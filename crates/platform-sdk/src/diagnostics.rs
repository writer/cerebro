//! Point-in-time operational health contracts for platform capabilities.
//!
//! Diagnostics report observed counters and capability states for one tenant.
//! These types contain no collection logic or consistency validator; the
//! implementation must gather a coherent, authorized snapshot and bound any
//! caller-visible strings before returning it.

use serde::Serialize;

use crate::{GraphRevision, TenantId};

/// Operational availability of one named capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// Capability is available and no material impairment is known.
    Healthy,
    /// Capability remains available with a known impairment.
    Degraded,
    /// Capability cannot proceed until an operator or dependency clears a gate.
    Blocked,
    /// Capability is reconstructing state and is not yet current.
    Rebuilding,
    /// Capability cannot currently serve the operation.
    Unavailable,
}

/// Point-in-time status for one deployment capability.
///
/// The state and reason code are caller-supplied and are not cross-validated by
/// the SDK. Collection boundaries should use a stable, bounded capability and
/// reason-code vocabulary rather than embedding sensitive backend messages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityHealth {
    /// Stable machine-readable capability name.
    pub capability: String,
    /// Observed availability state.
    pub state: CapabilityState,
    /// Optional machine-readable explanation for a non-healthy state.
    pub reason_code: Option<String>,
    /// Caller-supplied Unix-millisecond observation time.
    pub observed_at_unix_millis: i64,
}

/// Backlog observed between durable graph state and a projection.
///
/// The SDK does not enforce relationships among these fields; for example, it
/// permits a non-zero oldest age with zero pending records. The collector owns
/// a coherent sampling point and interpretation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectionLag {
    /// Non-zero graph revision visible at the projection boundary.
    pub graph_revision: GraphRevision,
    /// Durable outbox records not yet reflected in the projection.
    pub pending_outbox_records: u64,
    /// Age of the oldest pending record in milliseconds.
    pub oldest_pending_age_millis: u64,
}

/// Tenant-scoped operational snapshot across durability and capability signals.
///
/// Counters are observations, not authorization or correctness proofs. The SDK
/// does not require the top-level graph revision to equal the projection-lag
/// revision and does not derive capability state from any counter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationalDiagnostics {
    /// Tenant whose authorized operational state was sampled.
    pub tenant_id: TenantId,
    /// Append-log sequence visible at the sampling boundary.
    pub append_log_sequence: u64,
    /// Non-zero durable graph revision visible to the collector.
    pub graph_revision: GraphRevision,
    /// Current projection backlog observation.
    pub projection_lag: ProjectionLag,
    /// Count of rejected graph deltas in the collector's reporting window.
    pub rejected_deltas: u64,
    /// Count of parity mismatches in the collector's reporting window.
    pub parity_mismatches: u64,
    /// Count of resource-budget exhaustion events in the reporting window.
    pub budget_exhaustions: u64,
    /// Per-capability status records in collector-defined order.
    pub capabilities: Vec<CapabilityHealth>,
}
