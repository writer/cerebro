//! Authority-bound, exact-path deletion orchestration.

mod manifest;
mod receipt;
mod repository;

pub use manifest::{
    DeletionManifest, DeletionManifestBuildRequest, ManifestPathDeletion, bind_deletion_manifest,
};
pub use receipt::DeletionReceipt;
pub use repository::{DeletionPreflight, apply_deletion_manifest, verify_deletion_manifest};

#[cfg(test)]
use manifest::bind_deletion_manifest_for_test;
#[cfg(test)]
use repository::{apply_deletion_manifest_for_test, verify_deletion_manifest_for_test};

#[cfg(test)]
mod tests;
