//! Credential-free Aha! request, normalization, and projection kernel.
//!
//! The trusted host owns credential-reference resolution, bearer
//! authentication, redirects, deadlines, and bounded network I/O. The generic
//! Rust catalog connector remains collection authority until this provider
//! kernel is wired through the shared credential host.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod types;

pub use catalog::{AhaEventContract, AhaRuntimeDefinition};
pub use error::AhaError;
pub use family::AhaFamily;
pub use projection::{AhaEntityFact, AhaProjectionFacts, project_aha_records};
pub use types::{AhaCheckpointCandidate, AhaKernel, AhaPage, AhaRecord, AhaRequest};

#[cfg(test)]
mod tests;
