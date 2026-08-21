//! Credential-free GCP source normalization facade.
//!
//! Focused provider modules own GCS content inspection and IAM inventory
//! parity. This facade preserves their public API without accepting credentials
//! or performing provider I/O.

mod gcs;
mod iam;

pub use gcs::{GcpContentInspection, GcpDataClassification, GcpObjectContentKernel};
pub use iam::{
    GcpIamError, GcpIamFamily, GcpIamFilters, GcpIamKernel, GcpIamPage, GcpIamRecord, GcpIamRequest,
};
