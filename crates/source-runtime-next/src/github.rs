//! Credential-free GitHub request planning and response normalization.
//!
//! This module deliberately retains GitHub's audit, repository, Dependabot,
//! organization-inventory, pull-request, and secret-scanning contracts. It is
//! not the narrower generic issue/event/email connector catalog.

mod catalog;
mod cursor;
mod error;
mod normalize;
mod normalize_audit;
mod normalize_inventory;
mod normalize_security;
mod origin;
mod request;
mod response;
mod types;

pub use catalog::{GitHubEventContract, GitHubRuntimeDefinition};
pub use error::GitHubError;
pub use types::{
    GitHubActorResolution, GitHubCheckpointCandidate, GitHubContinuation, GitHubFamily,
    GitHubFilters, GitHubKernel, GitHubPage, GitHubRecord, GitHubRequest, GitHubRequestKind,
};

#[cfg(test)]
mod tests;
