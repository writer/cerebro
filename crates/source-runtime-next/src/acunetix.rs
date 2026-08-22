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
mod types;

pub use catalog::{AcunetixEventContract, AcunetixRuntimeDefinition};
pub use error::AcunetixError;
pub use family::AcunetixFamily;
pub use projection::{AcunetixEntityFact, AcunetixProjectionFacts, project_acunetix_records};
pub use types::{
    AcunetixCheckpointCandidate, AcunetixKernel, AcunetixPage, AcunetixRecord, AcunetixRequest,
};

#[cfg(test)]
mod tests;
