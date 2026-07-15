//! Durable control-plane primitives for Cerebro mandates and missions.
//!
//! This crate is intentionally free of network, database, graph, provider,
//! model, and transport dependencies. It owns stable identity and pure domain
//! behavior. Runtime adapters belong outside the kernel.

mod authority;
mod event;
mod identity;
mod mandate;
mod mission;
mod protocol;

pub use authority::{
    AuthorizationDecision, AuthorizationDenial, AuthorizationRequest, CapabilityGrant,
    DecisionReceipt, VerificationReceipt,
};
pub use event::{MissionAggregate, MissionEvent, MissionEventEnvelope, ReplayError};
pub use identity::{
    ActorId, DecisionId, GrantId, IdentifierError, MandateId, MissionId, RequestId, TenantId,
    VerificationId,
};
pub use mandate::{Mandate, MandateError, MandateInput, MandateStatus};
pub use mission::{Mission, MissionError, MissionInput, MissionState, MissionTransition};
pub use protocol::{CommandEnvelope, ControlCommand, ControlResponse, ProtocolError};

/// Identifies the first public schema revision of the native control kernel.
pub const SCHEMA_VERSION: &str = "cerebro.control-kernel.v1";
