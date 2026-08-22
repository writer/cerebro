//! Credential-free JumpCloud request, normalization, and projection kernel.
//!
//! The trusted host owns credential resolution, authentication, redirects,
//! deadlines, and bounded network I/O. This module accepts public source
//! configuration and already-bounded provider response bytes only.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod types;

pub use catalog::{JumpCloudEventContract, JumpCloudRuntimeDefinition};
pub use error::JumpCloudError;
pub use family::JumpCloudFamily;
pub use projection::{
    JumpCloudEntityFact, JumpCloudProjectionFacts, JumpCloudRelationFact, project_jumpcloud_records,
};
pub use types::{
    JumpCloudCheckpointCandidate, JumpCloudFilters, JumpCloudKernel, JumpCloudPage,
    JumpCloudRecord, JumpCloudRequest, JumpCloudResponseMetadata,
};

#[cfg(test)]
mod tests;
