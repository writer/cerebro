//! Credential-free Asana request, normalization, and projection kernel.
//!
//! The trusted host owns credential resolution, authentication, redirects,
//! deadlines, and bounded network I/O. This module accepts public source
//! configuration and already-bounded provider response bytes only.
//! Durable progress remains a host-side post-append and post-projection action.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod types;

pub use catalog::{AsanaEventContract, AsanaRuntimeDefinition};
pub use error::AsanaError;
pub use family::AsanaFamily;
pub use projection::{
    AsanaEntityFact, AsanaProjectionFacts, AsanaRelationFact, project_asana_records,
};
pub use types::{AsanaCheckpointCandidate, AsanaKernel, AsanaPage, AsanaRecord, AsanaRequest};

#[cfg(test)]
mod tests;
