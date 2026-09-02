//! Credential-free AbuseIPDB request, normalization, and projection kernel.
//!
//! The trusted host owns credential-reference resolution, `Key` header
//! authentication, redirects, deadlines, and bounded network I/O. This module
//! accepts authenticated tenant context, public filters, and bounded provider
//! response bytes only. The existing generic Rust catalog runtime remains the
//! collection authority until this kernel is integrated through the shared host.

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

pub use catalog::{AbuseIpDbEventContract, AbuseIpDbRuntimeDefinition};
pub use error::AbuseIpDbError;
pub use family::AbuseIpDbFamily;
pub use projection::{
    AbuseIpDbEntityFact, AbuseIpDbProjectionFacts, AbuseIpDbRelationFact, project_abuseipdb_records,
};
pub use types::{
    AbuseIpDbCheckpointCandidate, AbuseIpDbFilters, AbuseIpDbKernel, AbuseIpDbPage,
    AbuseIpDbRecord, AbuseIpDbRequest,
};

pub(crate) use source_execution::ABUSEIPDB_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
mod source_execution_tests;
#[cfg(test)]
mod tests;
