//! Durable control-plane primitives for Cerebro mandates and missions.
//!
//! This crate is intentionally free of network, database, graph, provider,
//! model, and transport dependencies. It owns stable identity and pure domain
//! behavior. Runtime adapters belong outside the kernel.

mod identity;
mod mandate;
mod mission;

pub use identity::{ActorId, IdentifierError, MandateId, MissionId, TenantId};
pub use mandate::{Mandate, MandateError, MandateInput, MandateStatus};
pub use mission::{Mission, MissionError, MissionInput, MissionState, MissionTransition};

/// Identifies the first public schema revision of the native control kernel.
pub const SCHEMA_VERSION: &str = "cerebro.control-kernel.v1";
