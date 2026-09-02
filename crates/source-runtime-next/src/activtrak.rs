//! Credential-free ActivTrak request, normalization, and projection kernel.
//!
//! The trusted host owns credential-reference resolution, `x-api-key`
//! authentication, redirects, deadlines, and bounded network I/O. This module
//! receives only authenticated tenant context, public request configuration,
//! and bounded provider response bytes. The generic Rust catalog connector
//! remains the authoritative collection path.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
#[path = "activtrak/source_execution.rs"]
mod source_execution;
mod types;

pub use catalog::{ActivTrakEventContract, ActivTrakRuntimeDefinition};
pub use error::ActivTrakError;
pub use family::ActivTrakFamily;
pub use projection::{ActivTrakEntityFact, ActivTrakProjectionFacts, project_activtrak_records};
pub use types::{
    ActivTrakCheckpointCandidate, ActivTrakKernel, ActivTrakPage, ActivTrakRecord, ActivTrakRequest,
};

pub(crate) use source_execution::ACTIVTRAK_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
#[path = "activtrak/source_execution_tests.rs"]
mod source_execution_tests;

#[cfg(test)]
mod tests;
