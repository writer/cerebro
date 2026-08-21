//! Portable AWS CodeBuild provider-local foundation.
//!
//! The facade exposes credential-free request planning and normalized records.
//! SigV4, egress authorization, checkpoints, and append-log ownership remain
//! with the shared runtime.

mod normalize;
mod request;
mod wire;

pub use request::AwsCodeBuildKernel;
pub use wire::{
    AwsCodeBuildBatch, AwsCodeBuildError, AwsCodeBuildFamily, AwsCodeBuildRecord,
    AwsCodeBuildRequest, AwsCodeBuildRequestKind,
};

#[cfg(test)]
use request::MAX_CURSOR_BYTES;
#[cfg(test)]
use wire::AWS_JSON_CONTENT_TYPE;
#[cfg(test)]
mod tests;
