//! Credential-free Slack request planning and response normalization.
//!
//! The kernel covers Slack Web API inventory and membership families plus the
//! Enterprise Grid Audit Logs API. It never receives or applies credential
//! bytes and performs no network or graph writes.

mod cursor;
mod error;
mod family;
mod normalize;
mod request;
mod response;
mod types;

pub use error::SlackError;
pub use family::SlackFamily;
pub use types::{SlackCheckpoint, SlackFilters, SlackKernel, SlackPage, SlackRecord, SlackRequest};

#[cfg(test)]
mod tests;
