use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use super::manifest::DeletionManifest;
use super::receipt::{DeletionReceipt, build_receipt};
use crate::MigratorError;
use crate::digest::{canonical_digest, reader_digest};
use crate::validation::validate_exact_file_path;

const PREFLIGHT_SCHEMA: &str = "cerebro.migrator.deletion-preflight/v1";

/// Deterministic evidence that every target passed repository and file preflight.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionPreflight {
    schema_version: String,
    content_digest: String,
    manifest_digest: String,
    base_sha: String,
    target_count: u64,
    total_bytes: u64,
}

impl DeletionPreflight {
    /// Returns the digest binding the preflight result.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Returns the number of targets fully checked without mutation.
    #[must_use]
    pub fn target_count(&self) -> u64 {
        self.target_count
    }

    /// Returns the total byte size measured during digest verification.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

pub(super) struct VerifiedPreflight {
    pub(super) public: DeletionPreflight,
    pub(super) targets: Vec<PreflightTarget>,
}

pub(super) struct PreflightTarget {
    pub(super) path: String,
    absolute_path: PathBuf,
    pub(super) before_content_digest: String,
    pub(super) bytes: u64,
}

/// Performs every repository, authority, target-type, tracked-file, and byte-
/// digest check without modifying the checkout.
pub fn verify_deletion_manifest(
    repository_root: &Path,
    manifest: &DeletionManifest,
) -> Result<DeletionPreflight, MigratorError> {
    let preflight = preflight(repository_root, manifest, false)?;
    Ok(preflight.public)
}

#[cfg(test)]
pub(super) fn verify_deletion_manifest_for_test(
    repository_root: &Path,
    manifest: &DeletionManifest,
) -> Result<DeletionPreflight, MigratorError> {
    let preflight = preflight(repository_root, manifest, true)?;
    Ok(preflight.public)
}

/// Fully preflights every target, then removes only the exact regular files in
/// the authority-bound manifest and returns a deterministic receipt.
///
/// No path is deleted unless the complete manifest passes preflight. Symbol
/// targets, directories, symlinks, untracked paths, patterns, and traversals fail
/// closed. The checkout is intentionally dirty after a successful apply so the
/// forward change can be inspected and committed normally.
pub fn apply_deletion_manifest(
    repository_root: &Path,
    manifest: &DeletionManifest,
) -> Result<DeletionReceipt, MigratorError> {
    let preflight = preflight(repository_root, manifest, false)?;
    remove_preflight_targets(&preflight)?;
    build_receipt(manifest, &preflight)
}

#[cfg(test)]
pub(super) fn apply_deletion_manifest_for_test(
    repository_root: &Path,
    manifest: &DeletionManifest,
) -> Result<DeletionReceipt, MigratorError> {
    let preflight = preflight(repository_root, manifest, true)?;
    remove_preflight_targets(&preflight)?;
    build_receipt(manifest, &preflight)
}

fn remove_preflight_targets(preflight: &VerifiedPreflight) -> Result<(), MigratorError> {
    for target in &preflight.targets {
        fs::remove_file(&target.absolute_path).map_err(|error| MigratorError::DeletionFailed {
            path: target.path.clone(),
            error: error.to_string(),
        })?;
    }
    Ok(())
}

fn preflight(
    repository_root: &Path,
    manifest: &DeletionManifest,
    allow_test_eligible: bool,
) -> Result<VerifiedPreflight, MigratorError> {
    #[cfg(test)]
    if allow_test_eligible {
        manifest.verify_for_test()?;
    } else {
        manifest.verify()?;
    }
    #[cfg(not(test))]
    {
        let _ = allow_test_eligible;
        manifest.verify()?;
    }
    let root = verify_repository_state(repository_root, manifest.base_sha())?;
    let mut targets = Vec::with_capacity(manifest.targets().len());
    let mut total_bytes = 0_u64;
    for target in manifest.targets() {
        let absolute_path = inspect_regular_file(&root, target.path())?;
        ensure_tracked(&root, target.path())?;
        let (actual, byte_count) = reader_digest(fs::File::open(&absolute_path)?)?;
        if actual != target.before_content_digest() {
            return Err(MigratorError::FileDigestMismatch {
                path: target.path().to_owned(),
                expected: target.before_content_digest().to_owned(),
                actual,
            });
        }
        total_bytes = total_bytes
            .checked_add(byte_count)
            .ok_or(MigratorError::ScoreOverflow)?;
        targets.push(PreflightTarget {
            path: target.path().to_owned(),
            absolute_path,
            before_content_digest: target.before_content_digest().to_owned(),
            bytes: byte_count,
        });
    }

    let target_count = u64::try_from(targets.len()).map_err(|_| MigratorError::ScoreOverflow)?;
    let mut public = DeletionPreflight {
        schema_version: PREFLIGHT_SCHEMA.to_owned(),
        content_digest: String::new(),
        manifest_digest: manifest.content_digest().to_owned(),
        base_sha: manifest.base_sha().to_owned(),
        target_count,
        total_bytes,
    };
    public.content_digest = canonical_digest(&DeletionPreflightPayload::from(&public))?;
    Ok(VerifiedPreflight { public, targets })
}

pub(super) fn verify_repository_state(
    repository_root: &Path,
    base_sha: &str,
) -> Result<PathBuf, MigratorError> {
    let root = fs::canonicalize(repository_root)?;
    let git_root = fs::canonicalize(git_stdout(
        &root,
        "resolve-root",
        ["rev-parse", "--show-toplevel"],
    )?)?;
    if root != git_root {
        return Err(MigratorError::RepositoryRootMismatch {
            requested: root.display().to_string(),
            actual: git_root.display().to_string(),
        });
    }
    let head = git_stdout(&root, "resolve-head", ["rev-parse", "HEAD"])?;
    if head != base_sha {
        return Err(MigratorError::BaseShaMismatch {
            expected: base_sha.to_owned(),
            actual: head,
        });
    }
    let status = git_bytes(
        &root,
        "check-clean-worktree",
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )?;
    if !status.is_empty() {
        return Err(MigratorError::DirtyWorktree);
    }
    Ok(root)
}

pub(super) fn inspect_regular_file(root: &Path, path: &str) -> Result<PathBuf, MigratorError> {
    validate_exact_file_path(path)?;
    let parts: Vec<&str> = path.split('/').collect();
    let mut current = root.to_path_buf();
    for part in &parts[..parts.len() - 1] {
        current.push(part);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            MigratorError::InvalidDeletionTarget {
                path: path.to_owned(),
                reason: format!("parent component cannot be inspected: {error}"),
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(MigratorError::InvalidDeletionTarget {
                path: path.to_owned(),
                reason: "a parent component is not a real directory".to_owned(),
            });
        }
    }
    current.push(parts[parts.len() - 1]);
    let metadata =
        fs::symlink_metadata(&current).map_err(|error| MigratorError::InvalidDeletionTarget {
            path: path.to_owned(),
            reason: format!("target cannot be inspected: {error}"),
        })?;
    if metadata.file_type().is_symlink() {
        return Err(MigratorError::InvalidDeletionTarget {
            path: path.to_owned(),
            reason: "symbolic links are not regular-file deletion targets".to_owned(),
        });
    }
    if !metadata.is_file() {
        return Err(MigratorError::InvalidDeletionTarget {
            path: path.to_owned(),
            reason: "target is not a regular file".to_owned(),
        });
    }
    Ok(current)
}

pub(super) fn ensure_tracked(root: &Path, path: &str) -> Result<(), MigratorError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "--literal-pathspecs",
            "ls-files",
            "--error-unmatch",
            "--",
            path,
        ])
        .output()?;
    if !output.status.success() {
        return Err(MigratorError::InvalidDeletionTarget {
            path: path.to_owned(),
            reason: "target is not tracked at the manifest base commit".to_owned(),
        });
    }
    Ok(())
}

fn git_stdout<const N: usize>(
    root: &Path,
    operation: &'static str,
    arguments: [&str; N],
) -> Result<String, MigratorError> {
    let bytes = git_bytes(root, operation, arguments)?;
    String::from_utf8(bytes)
        .map(|value| value.trim().to_owned())
        .map_err(|error| MigratorError::GitCommand {
            operation,
            error: error.to_string(),
        })
}

fn git_bytes<const N: usize>(
    root: &Path,
    operation: &'static str,
    arguments: [&str; N],
) -> Result<Vec<u8>, MigratorError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(MigratorError::GitCommand { operation, error });
    }
    Ok(output.stdout)
}

#[derive(Serialize)]
struct DeletionPreflightPayload<'a> {
    manifest_digest: &'a str,
    base_sha: &'a str,
    target_count: u64,
    total_bytes: u64,
}

impl<'a> From<&'a DeletionPreflight> for DeletionPreflightPayload<'a> {
    fn from(preflight: &'a DeletionPreflight) -> Self {
        Self {
            manifest_digest: &preflight.manifest_digest,
            base_sha: &preflight.base_sha,
            target_count: preflight.target_count,
            total_bytes: preflight.total_bytes,
        }
    }
}
