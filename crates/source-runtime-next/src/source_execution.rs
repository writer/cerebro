//! Credential-free source execution protocol for the standalone worker.
//!
//! The wire messages mirror the canonical `cerebro.v1` protobuf definitions.
//! The Go host owns credentials and all network I/O.

#[path = "source_execution/azure_authorization_policy.rs"]
mod azure_authorization_policy;
#[path = "source_execution/contract.rs"]
mod contract;
#[path = "source_execution/error.rs"]
mod error;
#[path = "source_execution/wire.rs"]
mod wire;

pub(crate) use azure_authorization_policy::{decode, plan};

#[cfg(test)]
#[path = "source_execution/tests.rs"]
mod tests;
