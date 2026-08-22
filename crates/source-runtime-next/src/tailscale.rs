//! Credential-free Tailscale request, normalization, and projection kernel.
//!
//! The trusted host owns credential-reference resolution, bearer authentication,
//! redirect policy, deadlines, and bounded network I/O. This module accepts
//! public source scope and already-bounded provider response bytes only. The Go
//! source remains authoritative until repository promotion evidence permits a
//! separate authority change.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod types;

pub use catalog::{TailscaleEventContract, TailscaleRuntimeDefinition};
pub use error::TailscaleError;
pub use family::TailscaleFamily;
pub use projection::{
    TailscaleEntityFact, TailscaleProjectionFacts, TailscaleRelationFact, project_tailscale_records,
};
pub use types::{
    TailscaleCheckpointCandidate, TailscaleKernel, TailscalePage, TailscaleRecord,
    TailscaleRequest, TailscaleResponseMetadata,
};

#[cfg(test)]
mod tests;
