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
mod source_execution;
mod types;

pub(crate) use source_execution::ASANA_SOURCE_EXECUTION_ADAPTERS;

pub use catalog::{AsanaEventContract, AsanaRuntimeDefinition};
pub use error::AsanaError;
pub use family::AsanaFamily;
pub use projection::{
    AsanaEntityFact, AsanaProjectionFacts, AsanaRelationFact, asana_users_graph_batch,
    project_asana_records,
};
pub use types::{AsanaCheckpointCandidate, AsanaKernel, AsanaPage, AsanaRecord, AsanaRequest};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod users_catalog_tests;

#[cfg(test)]
mod users_failure_tests;

#[cfg(test)]
mod users_graph_projection_tests;

#[cfg(test)]
mod users_graph_rejection_tests;

#[cfg(test)]
mod users_pagination_tests;

#[cfg(test)]
mod users_publication_tests;

#[cfg(test)]
mod users_test_support;
