//! Credential-free Akeneo request, normalization, and projection kernel.
//!
//! The trusted host owns credential-reference resolution, bearer authentication,
//! redirects, deadlines, and bounded network I/O. The generic catalog/Go
//! compatibility path remains collection authority until production promotion.

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
#[cfg(test)]
mod source_execution_tests;
mod types;

pub use catalog::{AkeneoEventContract, AkeneoRuntimeDefinition};
pub use error::AkeneoError;
pub use family::AkeneoFamily;
pub use projection::{AkeneoEntityFact, AkeneoProjectionFacts, project_akeneo_records};
pub use types::{
    AkeneoCheckpointCandidate, AkeneoKernel, AkeneoPage, AkeneoRecord, AkeneoRequest, AkeneoScope,
};

#[allow(unused_imports)]
pub(crate) use source_execution::AKENEO_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
mod tests;
