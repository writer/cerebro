use serde::{Deserialize, Serialize};

mod envelope;
mod evidence;
mod payload;
mod receipt;
mod validation;

pub use envelope::{DecodedWirePayload, ExternalEventEnvelope, WireSignature};
pub use evidence::{EvidenceCompleteness, EvidenceFreshness, WireEvidenceState};
pub use payload::{
    AgentActionStage, AgentActivity, AgentCapability, ConnectorManifest, EndpointNetworkProfile,
    EndpointOwnership, EndpointSessionLease, EndpointTelemetry, MetricSnapshot, RemediationOutcome,
    ScannerFinding, ScannerSeverity, ScannerValidationState, ThreatIndicatorKind,
    ThreatIntelligenceObservation, ThreatPromotionReason, ThreatVerdict,
};
pub use receipt::{WireIngestOutcome, WireIngestReason, WireIngestReceipt};

/// Version of the common external-event envelope.
pub const EXTERNAL_EVENT_SCHEMA_V1: &str = "cerebro.external-event/v1";
/// Agent activity payload schema.
pub const AGENT_ACTIVITY_SCHEMA_V1: &str = "cerebro/agent/activity/v1";
/// Endpoint telemetry payload schema.
pub const ENDPOINT_TELEMETRY_SCHEMA_V1: &str = "cerebro/endpoint/telemetry/v1";
/// Endpoint session-lease payload schema.
pub const ENDPOINT_SESSION_LEASE_SCHEMA_V1: &str = "cerebro/endpoint/session-lease/v1";
/// Threat-intelligence payload schema.
pub const THREAT_INTELLIGENCE_SCHEMA_V1: &str = "cerebro/threat-intelligence/observation/v1";
/// Remediation outcome payload schema.
pub const REMEDIATION_OUTCOME_SCHEMA_V1: &str = "cerebro/remediation/outcome/v1";
/// Metric snapshot payload schema.
pub const METRIC_SNAPSHOT_SCHEMA_V1: &str = "cerebro/metric/snapshot/v1";
/// Scanner finding payload schema.
pub const SCANNER_FINDING_SCHEMA_V1: &str = "cerebro/scanner/finding/v1";
/// Declarative connector-manifest payload schema.
pub const CONNECTOR_MANIFEST_SCHEMA_V1: &str = "cerebro/connector/manifest/v1";
/// Agent capability payload schema.
pub const AGENT_CAPABILITY_SCHEMA_V1: &str = "cerebro/agent/capability/v1";

const SIGNING_DOMAIN_V1: &str = "cerebro.external-event-signature/v1";
const MAX_ID_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 1_024;
const MAX_PAYLOAD_BYTES: usize = 256 * 1_024;
const MAX_PAYLOAD_DEPTH: usize = 32;
const MAX_PAYLOAD_NODES: usize = 8_192;
const MAX_REFS: usize = 512;
const MAX_SESSION_LEASE_MS: u64 = 60 * 60 * 1_000;

/// Closed set of portable payload families admitted through the common wire.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireContractFamily {
    AgentActivity,
    EndpointTelemetry,
    EndpointSessionLease,
    ThreatIntelligence,
    RemediationOutcome,
    MetricSnapshot,
    ScannerFinding,
    ConnectorManifest,
    AgentCapability,
}

impl WireContractFamily {
    /// Returns the only payload schema admitted for this family in v1.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::AgentActivity => AGENT_ACTIVITY_SCHEMA_V1,
            Self::EndpointTelemetry => ENDPOINT_TELEMETRY_SCHEMA_V1,
            Self::EndpointSessionLease => ENDPOINT_SESSION_LEASE_SCHEMA_V1,
            Self::ThreatIntelligence => THREAT_INTELLIGENCE_SCHEMA_V1,
            Self::RemediationOutcome => REMEDIATION_OUTCOME_SCHEMA_V1,
            Self::MetricSnapshot => METRIC_SNAPSHOT_SCHEMA_V1,
            Self::ScannerFinding => SCANNER_FINDING_SCHEMA_V1,
            Self::ConnectorManifest => CONNECTOR_MANIFEST_SCHEMA_V1,
            Self::AgentCapability => AGENT_CAPABILITY_SCHEMA_V1,
        }
    }
}

#[cfg(test)]
mod tests;
