//! Credential-free Discord request planning and response normalization kernel.
//!
//! The kernel models the public HTTP contract without holding a bot token or
//! performing network I/O. Checked-in test vectors are normalized examples;
//! they are not live provider captures and do not carry provider provenance.

mod cursor;
mod error;
mod family;
mod normalize;
mod request;
mod response;
// Provider-local adapters remain intentionally unreachable from the shared
// dispatcher until a later authority change qualifies each family.
#[cfg_attr(not(test), allow(dead_code))]
mod source_execution;
mod types;
mod wire;

pub use error::DiscordError;
pub use family::DiscordFamily;
pub use types::{DiscordKernel, DiscordPage, DiscordRecord, DiscordRequest};

#[cfg(test)]
mod audit_log_tests;
#[cfg(test)]
mod tests;
