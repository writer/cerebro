//! Credential-free Cloudflare request, response, cursor, and normalization kernel.
//!
//! The kernel covers the `cloudflare` source catalog. It never receives an API
//! token: the trusted host applies the declared bearer credential after the
//! request has passed the origin and scope checks in this module.

mod cursor;
mod error;
mod family;
mod kernel;
mod normalize;
mod origin;
#[allow(dead_code)]
mod source_execution;

pub use error::CloudflareError;
pub use family::{CloudflareFamily, CloudflareScope};
pub use kernel::{
    CloudflareKernel, CloudflarePage, CloudflareRecord, CloudflareRequest, CloudflareRequestKind,
};

#[allow(unused_imports)]
pub(crate) use source_execution::CLOUDFLARE_SOURCE_EXECUTION_ADAPTERS;

#[cfg(test)]
mod source_execution_tests;

#[cfg(test)]
mod tests;
