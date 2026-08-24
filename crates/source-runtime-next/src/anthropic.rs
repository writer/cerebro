//! Credential-free Anthropic Admin and Compliance API runtime kernel.
//!
//! The kernel compiles the checked-in source family contract into bounded GET
//! requests and canonical events. A trusted host remains responsible for
//! credential resolution, authentication, network I/O, redirects, deadlines,
//! and durable append/projection/checkpoint ordering.

mod error;
mod family;
mod mappings;
mod normalize;
mod request;
mod response;
// Provider-local adapters remain intentionally unreachable from the shared
// dispatcher until a later authority change qualifies each family.
#[cfg_attr(not(test), allow(dead_code))]
mod source_execution;
mod types;

pub use error::AnthropicError;
pub use family::{AnthropicAuthentication, AnthropicFamily};
pub use types::{
    AnthropicKernel, AnthropicPage, AnthropicRecord, AnthropicRequest, AnthropicScope,
};

#[cfg(test)]
mod tests;
