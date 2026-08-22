//! Credential-free OpenAI organization-governance collection kernel.
//!
//! The kernel compiles the closed OpenAI family table into bounded request
//! descriptions and normalizes provider response bytes. Authentication bytes,
//! redirect handling, and network execution remain outside this module.

mod error;
mod family;
mod normalize;
mod request;
mod response;

pub use error::OpenAiError;
pub use family::OpenAiFamily;
pub use request::{OpenAiAuthRequirement, OpenAiKernel, OpenAiRequest, OpenAiRequestInput};
pub use response::{OpenAiCheckpoint, OpenAiPage, OpenAiRecord};

#[cfg(test)]
mod tests;
