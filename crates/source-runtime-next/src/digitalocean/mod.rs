//! Credential-free DigitalOcean request, normalization, and parity kernel.
//!
//! The trusted host owns credential-reference resolution, Bearer authentication,
//! redirects, deadlines, and bounded network I/O. The closed Rust dispatcher
//! owns request planning, response normalization, validation, and checkpoint
//! proposals for every cataloged DigitalOcean family. The existing Go
//! projector remains authoritative for graph projection.

mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod source_execution;
mod types;

pub(crate) use source_execution::DIGITALOCEAN_SOURCE_EXECUTION_ADAPTERS;

pub use error::DigitalOceanError;
pub use family::DigitalOceanFamily;
pub use projection::{
    DigitalOceanEntityFact, DigitalOceanLinkFact, DigitalOceanProjectionFacts,
    project_digitalocean_records,
};
pub use types::{
    DigitalOceanCheckpointCandidate, DigitalOceanKernel, DigitalOceanOperation, DigitalOceanPage,
    DigitalOceanRecord, DigitalOceanRequest,
};

#[cfg(test)]
mod tests;
