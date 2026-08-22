//! AWS account-contact request and response runtime kernel.
//!
//! This provider-local boundary plans credential-free AWS Account requests,
//! validates bounded responses, and emits the redacted Go-compatible posture
//! record. Credentials, network execution, durable commits, and projection
//! remain owned by the trusted runtime host.

mod kernel;
mod model;
mod response;

pub use kernel::AwsAccountContactKernel;
pub use model::{
    AwsAccountContactError, AwsAccountContactOutcome, AwsAccountContactPage,
    AwsAccountContactRecord, AwsAccountContactRequest, AwsAccountContactRequestKind,
};

#[cfg(test)]
mod tests;
