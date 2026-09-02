//! Credential-free Ada Support request, normalization, and projection kernel.
//!
//! The trusted host owns credential-reference resolution, bearer authentication,
//! redirects, deadlines, and bounded network I/O. The generic Rust catalog
//! connector remains collection authority until this provider kernel is wired
//! through the shared credential host.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod source_execution;
mod types;

pub use catalog::{AdaSupportEventContract, AdaSupportRuntimeDefinition};
pub use error::AdaSupportError;
pub use family::AdaSupportFamily;
pub use projection::{
    AdaSupportEntityFact, AdaSupportProjectionFacts, project_ada_support_records,
};
pub use types::{
    AdaSupportCheckpointCandidate, AdaSupportKernel, AdaSupportPage, AdaSupportRecord,
    AdaSupportRequest,
};

pub(crate) use source_execution::ADA_SUPPORT_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
mod source_execution_tests;

#[cfg(test)]
mod tests;
