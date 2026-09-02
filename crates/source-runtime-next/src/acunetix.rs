//! Credential-free Acunetix request, normalization, and projection kernel.
//!
//! The trusted host owns credential-reference resolution, `X-Auth`
//! authentication, redirects, deadlines, and bounded network I/O. The kernel
//! accepts only authenticated tenant context, a public provider origin, and
//! bounded response bytes. The generic Rust catalog connector remains the
//! authoritative collection path.

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

pub use catalog::{AcunetixEventContract, AcunetixRuntimeDefinition};
pub use error::AcunetixError;
pub use family::AcunetixFamily;
pub use projection::{AcunetixEntityFact, AcunetixProjectionFacts, project_acunetix_records};
pub use types::{
    AcunetixCheckpointCandidate, AcunetixKernel, AcunetixPage, AcunetixRecord, AcunetixRequest,
};

#[allow(unused_imports)]
pub(crate) use source_execution::ACUNETIX_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
mod source_execution_tests;

#[cfg(test)]
mod tests;
