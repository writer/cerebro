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
#[allow(dead_code)]
mod source_execution;
mod types;

pub use catalog::{AdpEventContract, AdpRuntimeDefinition};
pub use error::AdpError;
pub use family::AdpFamily;
pub use projection::{AdpEntityFact, AdpProjectionFacts, project_adp_records};
pub use types::{AdpCheckpointCandidate, AdpKernel, AdpPage, AdpRecord, AdpRequest};

#[allow(unused_imports)]
pub(crate) use source_execution::ADP_WORKFORCE_NOW_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
mod source_execution_tests;

#[cfg(test)]
mod tests;
