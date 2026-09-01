//! Credential-free Abnormal Security request, normalization, and projection kernel.
//!
//! The trusted host owns bearer-token resolution and application, redirects,
//! deadlines, and bounded network I/O. This module receives authenticated
//! tenant context, a public provider origin, and bounded response bytes only.
//! The generic Rust catalog connector remains collection authority.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
#[path = "abnormal_security/source_execution.rs"]
mod source_execution;
mod types;

pub use catalog::{AbnormalSecurityEventContract, AbnormalSecurityRuntimeDefinition};
pub use error::AbnormalSecurityError;
pub use family::AbnormalSecurityFamily;
pub use projection::{
    AbnormalSecurityEntityFact, AbnormalSecurityProjectionFacts, project_abnormal_security_records,
};
pub use types::{
    AbnormalSecurityCheckpointCandidate, AbnormalSecurityKernel, AbnormalSecurityPage,
    AbnormalSecurityRecord, AbnormalSecurityRequest,
};

pub(crate) use source_execution::ABNORMAL_SECURITY_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
#[path = "abnormal_security/source_execution_tests.rs"]
mod source_execution_tests;

#[cfg(test)]
mod tests;
