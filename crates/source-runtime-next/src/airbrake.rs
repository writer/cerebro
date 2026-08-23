//! Credential-free Airbrake request, normalization, and projection kernel.
//!
//! The trusted host owns credential-reference resolution, query-parameter
//! authentication, redirects, deadlines, and bounded network I/O. The generic
//! Rust catalog connector remains collection authority until this provider
//! kernel is wired through the shared credential host.

mod catalog;
mod error;
mod family;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod types;

pub use catalog::{AirbrakeEventContract, AirbrakeRuntimeDefinition};
pub use error::AirbrakeError;
pub use family::AirbrakeFamily;
pub use projection::{AirbrakeEntityFact, AirbrakeProjectionFacts, project_airbrake_records};
pub use types::{
    AirbrakeCheckpointCandidate, AirbrakeKernel, AirbrakePage, AirbrakeRecord, AirbrakeRequest,
};

#[cfg(test)]
mod tests;
