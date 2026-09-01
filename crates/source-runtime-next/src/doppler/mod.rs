//! Credential-free Doppler collection adapters.
//!
//! The trusted host owns credential redemption, Bearer authentication,
//! redirects, deadlines, and network I/O. This module plans the three closed
//! Doppler reads and normalizes bounded provider responses without accepting
//! credential material.

mod error;
mod family;
mod normalize;
mod origin;
mod request;
mod response;
mod source_execution;
mod types;

pub(crate) use source_execution::DOPPLER_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
mod tests;
