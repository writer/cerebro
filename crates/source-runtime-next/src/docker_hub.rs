//! Credential-free Docker Hub repository request and response kernel.
//!
//! The trusted host owns credential-reference resolution, optional bearer
//! authentication, redirects, deadlines, and bounded network I/O. This module
//! accepts public scope and bounded provider bytes only. The existing catalog
//! runtime remains authoritative until repository parity earns promotion.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod types;

pub use catalog::{DockerHubEventContract, DockerHubRuntimeDefinition};
pub use error::DockerHubError;
pub use family::DockerHubFamily;
pub use projection::{DockerHubEntityFact, DockerHubProjectionFacts, project_docker_hub_records};
pub use types::{
    DockerHubCheckpointCandidate, DockerHubKernel, DockerHubPage, DockerHubRecord, DockerHubRequest,
};

#[cfg(test)]
mod tests;
