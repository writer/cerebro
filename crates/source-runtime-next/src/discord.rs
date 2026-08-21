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
mod types;
mod wire;

pub use error::DiscordError;
pub use family::DiscordFamily;
pub use types::{DiscordKernel, DiscordPage, DiscordRecord, DiscordRequest};

#[cfg(test)]
mod tests;
