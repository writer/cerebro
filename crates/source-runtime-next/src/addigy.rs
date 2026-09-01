//! Credential-free Addigy request, normalization, and projection kernel.
//!
//! The trusted host owns credential-reference resolution, x-api-key
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
mod source_execution;
#[cfg(test)]
mod source_execution_tests;
mod types;

pub use catalog::{AddigyEventContract, AddigyRuntimeDefinition};
pub use error::AddigyError;
pub use family::AddigyFamily;
pub use projection::{AddigyEntityFact, AddigyProjectionFacts, project_addigy_records};
pub use types::{AddigyCheckpointCandidate, AddigyKernel, AddigyPage, AddigyRecord, AddigyRequest};

pub(crate) use source_execution::ADDIGY_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
mod tests;
