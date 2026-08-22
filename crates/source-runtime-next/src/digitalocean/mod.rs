//! Credential-free DigitalOcean request, normalization, and parity kernel.
//!
//! The trusted host owns credential-reference resolution, Bearer authentication,
//! redirects, deadlines, and bounded network I/O. The existing Go source and
//! projector remain authoritative until shared registration and production
//! qualification land separately.

mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod types;

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
