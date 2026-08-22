//! Credential-free Okta request planning and response normalization kernel.
//!
//! The trusted runtime host owns SSWS credential resolution and network I/O.
//! This module accepts only a public Okta origin, tenant identity, bounded
//! selectors, response bytes, and response metadata.

mod cursor;
mod error;
mod family;
mod normalize;
mod origin;
mod request;
mod response;
mod types;

pub use error::OktaError;
pub use family::OktaFamily;
pub use types::{OktaFilters, OktaKernel, OktaPage, OktaRecord, OktaRequest, OktaResponse};

#[cfg(test)]
mod tests;
