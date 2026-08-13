#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Durable control-plane primitives for Cerebro mandates and missions.
//!
//! This crate is intentionally free of network, database, graph, provider,
//! model, and transport dependencies. It owns stable identity and pure domain
//! behavior. Runtime adapters belong outside the kernel.

mod authority;
mod belief;
mod commitment;
mod conversation;
mod event;
mod identity;
mod mandate;
mod mission;
mod plan;
mod protocol;
mod supervisor;
mod vendor_use;
mod wake;

pub use authority::{
    AuthorizationDecision, AuthorizationDenial, AuthorizationRequest, CapabilityGrant,
    DecisionReceipt, VerificationReceipt,
};
pub use belief::{Belief, BeliefBasis, BeliefError, BeliefInput, BeliefRevision, BeliefVerdict};
pub use commitment::{
    Commitment, CommitmentError, CommitmentInput, CommitmentState, CommitmentTransition,
};
pub use conversation::{
    ConversationResolution, EncounterProfile, ExecutionDepth, MissionReference,
    resolve_conversation, route_execution_depth,
};
pub use event::{MissionAggregate, MissionEvent, MissionEventEnvelope, ReplayError};
pub use identity::{
    ActorId, BeliefId, CommitmentId, ConversationId, DecisionId, GrantId, IdentifierError,
    MandateId, MissionId, PlanId, RequestId, TenantId, VerificationId, WakeConditionId,
};
pub use mandate::{Mandate, MandateError, MandateInput, MandateStatus};
pub use mission::{Mission, MissionError, MissionInput, MissionState, MissionTransition};
pub use plan::{PlanError, PlanRevision, PlanStep};
pub use protocol::{CommandEnvelope, ControlCommand, ControlResponse, ProtocolError};
pub use supervisor::{MissionDirective, SupervisorSnapshot, next_directive};
pub use vendor_use::{
    ProviderPermission, ProviderPermissionAccess, VendorReviewDecision, VendorUseApproval,
    VendorUseDecision, VendorUseDenial, VendorUseObservation, VendorUseObservationKind,
    VendorUsePlatform, VendorUsePolicy, VendorUseState, evaluate_vendor_use,
};
pub use wake::{
    WakeCondition, WakeConditionError, WakeConditionKind, WakeConditionState, WakeSignal,
};

/// Identifies the first public schema revision of the native control kernel.
pub const SCHEMA_VERSION: &str = "cerebro.control-kernel.v1";
