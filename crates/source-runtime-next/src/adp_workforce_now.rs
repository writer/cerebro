//! Credential-free ADP Workforce Now request and normalization kernel.
//!
//! The trusted host owns OAuth token redemption, mutual TLS identity,
//! authentication headers, redirects, deadlines, and bounded network I/O. The
//! generic Rust catalog connector remains collection authority until this
//! provider kernel is wired through the shared credential host.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod types;

pub use catalog::{AdpEventContract, AdpRuntimeDefinition};
pub use error::AdpError;
pub use family::AdpFamily;
pub use projection::{AdpEntityFact, AdpProjectionFacts, project_adp_records};
pub use types::{AdpCheckpointCandidate, AdpKernel, AdpPage, AdpRecord, AdpRequest};

#[cfg(test)]
mod tests;
