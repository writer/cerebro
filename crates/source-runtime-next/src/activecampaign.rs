//! Credential-free ActiveCampaign request, normalization, and projection kernel.
//!
//! The trusted host owns credential-reference resolution, `Api-Token` header
//! authentication, redirects, deadlines, and bounded network I/O. This module
//! accepts authenticated tenant context, a validated account origin, and
//! bounded provider response bytes only. The generic Rust catalog connector
//! remains collection authority until this kernel is integrated through the
//! shared credential host.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod types;

pub use catalog::{ActiveCampaignEventContract, ActiveCampaignRuntimeDefinition};
pub use error::ActiveCampaignError;
pub use family::ActiveCampaignFamily;
pub use projection::{
    ActiveCampaignEntityFact, ActiveCampaignProjectionFacts, project_activecampaign_records,
};
pub use types::{
    ActiveCampaignCheckpointCandidate, ActiveCampaignKernel, ActiveCampaignPage,
    ActiveCampaignRecord, ActiveCampaignRequest,
};

#[cfg(test)]
mod tests;
