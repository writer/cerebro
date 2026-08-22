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

#[cfg(test)]
mod tests;
