use serde::{Deserialize, Serialize};

use super::manifest::DeletionManifest;
use super::repository::VerifiedPreflight;
use crate::MigratorError;
use crate::digest::canonical_digest;
use crate::validation::{validate_digest, validate_exact_file_path, validate_git_sha};

const RECEIPT_SCHEMA: &str = "cerebro.migrator.deletion-receipt/v1";

/// One exact file recorded in a successful deletion receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeletedPathReceipt {
    path: String,
    before_content_digest: String,
    bytes: u64,
}

/// Deterministic content-bound receipt emitted after all exact files are removed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionReceipt {
    schema_version: String,
    content_digest: String,
    manifest_digest: String,
    preflight_digest: String,
    base_sha: String,
    deleted_paths: Vec<DeletedPathReceipt>,
    deleted_files: u64,
    deleted_bytes: u64,
}

impl DeletionReceipt {
    /// Returns the digest binding the complete deletion receipt payload.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Returns the number of exact regular files removed.
    #[must_use]
    pub fn deleted_files(&self) -> u64 {
        self.deleted_files
    }

    /// Returns the sum of bytes verified and removed.
    #[must_use]
    pub fn deleted_bytes(&self) -> u64 {
        self.deleted_bytes
    }

    /// Returns deleted repository-relative paths in lexical manifest order.
    pub fn deleted_paths(&self) -> impl Iterator<Item = &str> {
        self.deleted_paths.iter().map(|target| target.path.as_str())
    }

    /// Recomputes all structural invariants and the deterministic receipt digest.
    pub fn verify(&self) -> Result<(), MigratorError> {
        if self.schema_version != RECEIPT_SCHEMA {
            return Err(MigratorError::InvalidField {
                field: "deletion receipt schema_version",
                reason: format!("unsupported value {}", self.schema_version),
            });
        }
        validate_digest(&self.manifest_digest, "receipt manifest digest")?;
        validate_digest(&self.preflight_digest, "receipt preflight digest")?;
        validate_git_sha(&self.base_sha, "receipt base SHA")?;
        validate_digest(&self.content_digest, "deletion receipt content digest")?;
        if self
            .deleted_paths
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(MigratorError::InvalidField {
                field: "deleted receipt paths",
                reason: "values must be sorted and unique".to_owned(),
            });
        }
        let mut deleted_bytes = 0_u64;
        for target in &self.deleted_paths {
            validate_exact_file_path(&target.path)?;
            validate_digest(
                &target.before_content_digest,
                "receipt before-content digest",
            )?;
            deleted_bytes = deleted_bytes
                .checked_add(target.bytes)
                .ok_or(MigratorError::ScoreOverflow)?;
        }
        if self.deleted_files != self.deleted_paths.len() as u64
            || self.deleted_bytes != deleted_bytes
        {
            return Err(MigratorError::InvalidField {
                field: "deletion receipt totals",
                reason: "must exactly match the deleted path records".to_owned(),
            });
        }
        let actual = canonical_digest(&DeletionReceiptPayload::from(self))?;
        if actual != self.content_digest {
            return Err(MigratorError::DigestMismatch {
                expected: self.content_digest.clone(),
                actual,
            });
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct DeletionReceiptPayload<'a> {
    manifest_digest: &'a str,
    preflight_digest: &'a str,
    base_sha: &'a str,
    deleted_paths: &'a [DeletedPathReceipt],
    deleted_files: u64,
    deleted_bytes: u64,
}

impl<'a> From<&'a DeletionReceipt> for DeletionReceiptPayload<'a> {
    fn from(receipt: &'a DeletionReceipt) -> Self {
        Self {
            manifest_digest: &receipt.manifest_digest,
            preflight_digest: &receipt.preflight_digest,
            base_sha: &receipt.base_sha,
            deleted_paths: &receipt.deleted_paths,
            deleted_files: receipt.deleted_files,
            deleted_bytes: receipt.deleted_bytes,
        }
    }
}

pub(super) fn build_receipt(
    manifest: &DeletionManifest,
    preflight: &VerifiedPreflight,
) -> Result<DeletionReceipt, MigratorError> {
    let deleted_paths: Vec<DeletedPathReceipt> = preflight
        .targets
        .iter()
        .map(|target| DeletedPathReceipt {
            path: target.path.clone(),
            before_content_digest: target.before_content_digest.clone(),
            bytes: target.bytes,
        })
        .collect();
    let mut receipt = DeletionReceipt {
        schema_version: RECEIPT_SCHEMA.to_owned(),
        content_digest: String::new(),
        manifest_digest: manifest.content_digest().to_owned(),
        preflight_digest: preflight.public.content_digest().to_owned(),
        base_sha: manifest.base_sha().to_owned(),
        deleted_files: preflight.public.target_count(),
        deleted_bytes: preflight.public.total_bytes(),
        deleted_paths,
    };
    receipt.content_digest = canonical_digest(&DeletionReceiptPayload::from(&receipt))?;
    Ok(receipt)
}
