//! Credential-free GCP IAM contracts and focused provider dispatch.

mod cursor;
mod error;
mod kernel;
mod model;
mod normalize;
mod origin;
mod service_account;
mod service_account_key;

#[cfg(test)]
mod tests;

pub use error::GcpIamError;
pub use kernel::GcpIamKernel;
pub use model::{GcpIamFamily, GcpIamFilters, GcpIamPage, GcpIamRecord, GcpIamRequest};
