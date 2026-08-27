use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::digest::{canonical_digest, reader_digest};
use crate::validation::{validate_digest, validate_exact_file_path, validate_git_sha};
use crate::{BatchPlan, DeletionTarget, MigrationStatus, MigrationUnit, MigratorError};

const MANIFEST_SCHEMA: &str = "cerebro.migrator.deletion-manifest/v2";
const PREFLIGHT_SCHEMA: &str = "cerebro.migrator.deletion-preflight/v1";
const RECEIPT_SCHEMA: &str = "cerebro.migrator.deletion-receipt/v1";
const MAX_TARGETS: usize = 100_000;

/// Self-contained input for building a deletion manifest from verified authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionManifestBuildRequest {
    /// Content-bound maximum-deletion plan.
    pub plan: BatchPlan,
    /// Bound migration-unit documents selected by the plan.
    pub units: Vec<MigrationUnit>,
}

impl DeletionManifestBuildRequest {
    /// Verifies the plan and selected units, then binds current exact file bytes.
    pub fn bind(self, repository_root: &Path) -> Result<DeletionManifest, MigratorError> {
        bind_deletion_manifest(repository_root, self.plan, self.units)
    }
}

/// One exact file and its digest at the manifest's clean base commit.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPathDeletion {
    path: String,
    before_content_digest: String,
}

impl ManifestPathDeletion {
    /// Returns the exact repository-relative regular-file path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the SHA-256 digest of bytes verified before deletion.
    #[must_use]
    pub fn before_content_digest(&self) -> &str {
        &self.before_content_digest
    }
}

/// Immutable manifest bound to a verified plan, its selected eligible units, and
/// exact file bytes from a clean base checkout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionManifest {
    schema_version: String,
    content_digest: String,
    base_sha: String,
    batch_plan: BatchPlan,
    selected_units: Vec<MigrationUnit>,
    targets: Vec<ManifestPathDeletion>,
}

impl DeletionManifest {
    /// Parses and verifies a previously emitted manifest document.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, MigratorError> {
        let document: Self = serde_json::from_slice(bytes)?;
        document.verify()?;
        Ok(document)
    }

    /// Revalidates plan authority, selected unit eligibility, exact target union,
    /// normalization, and the complete manifest content digest.
    pub fn verify(&self) -> Result<(), MigratorError> {
        self.verify_internal(false)
    }

    #[cfg(test)]
    fn verify_for_test(&self) -> Result<(), MigratorError> {
        self.verify_internal(true)
    }

    fn verify_internal(&self, allow_test_eligible: bool) -> Result<(), MigratorError> {
        if self.schema_version != MANIFEST_SCHEMA {
            return Err(MigratorError::InvalidField {
                field: "deletion manifest schema_version",
                reason: format!("unsupported value {}", self.schema_version),
            });
        }
        validate_git_sha(&self.base_sha, "deletion manifest base SHA")?;
        if self.base_sha != self.batch_plan.base_sha() {
            return Err(MigratorError::BaseShaMismatch {
                expected: self.batch_plan.base_sha().to_owned(),
                actual: self.base_sha.clone(),
            });
        }
        let expected_paths =
            validate_plan_authority(&self.batch_plan, &self.selected_units, allow_test_eligible)?;
        validate_bound_targets(&self.targets, &expected_paths)?;
        validate_digest(&self.content_digest, "deletion manifest content digest")?;
        let actual = canonical_digest(&DeletionManifestPayload::from(self))?;
        if actual != self.content_digest {
            return Err(MigratorError::DigestMismatch {
                expected: self.content_digest.clone(),
                actual,
            });
        }
        Ok(())
    }

    /// Returns the exact repository revision bound into the manifest.
    #[must_use]
    pub fn base_sha(&self) -> &str {
        &self.base_sha
    }

    /// Returns exact normalized path targets in lexical order.
    #[must_use]
    pub fn targets(&self) -> &[ManifestPathDeletion] {
        &self.targets
    }

    /// Returns the digest binding the plan, units, and exact target bytes.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

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

/// One exact file recorded in a successful deletion receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeletedPathReceipt {
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

/// Builds a manifest only from a verified batch plan and the exact bound unit
/// documents selected by that plan.
///
/// Every selected unit must be `deletion_eligible`, its content digest must match
/// the plan, and every deletion target must be an exact path. The builder requires
/// a clean checkout at the plan's exact base commit and computes every before-byte
/// digest itself; callers cannot assert eligibility or file digests in JSON.
pub fn bind_deletion_manifest(
    repository_root: &Path,
    plan: BatchPlan,
    units: Vec<MigrationUnit>,
) -> Result<DeletionManifest, MigratorError> {
    bind_deletion_manifest_internal(repository_root, plan, units, false)
}

#[cfg(test)]
fn bind_deletion_manifest_for_test(
    repository_root: &Path,
    plan: BatchPlan,
    units: Vec<MigrationUnit>,
) -> Result<DeletionManifest, MigratorError> {
    bind_deletion_manifest_internal(repository_root, plan, units, true)
}

fn bind_deletion_manifest_internal(
    repository_root: &Path,
    plan: BatchPlan,
    mut units: Vec<MigrationUnit>,
    allow_test_eligible: bool,
) -> Result<DeletionManifest, MigratorError> {
    units.sort_by(|left, right| left.id().cmp(right.id()));
    let expected_paths = validate_plan_authority(&plan, &units, allow_test_eligible)?;
    let root = verify_repository_state(repository_root, plan.base_sha())?;
    let targets = bind_targets(&root, &expected_paths)?;
    let mut manifest = DeletionManifest {
        schema_version: MANIFEST_SCHEMA.to_owned(),
        content_digest: String::new(),
        base_sha: plan.base_sha().to_owned(),
        batch_plan: plan,
        selected_units: units,
        targets,
    };
    manifest.content_digest = canonical_digest(&DeletionManifestPayload::from(&manifest))?;
    if allow_test_eligible {
        #[cfg(test)]
        manifest.verify_for_test()?;
        #[cfg(not(test))]
        return Err(MigratorError::ManifestIneligible);
    } else {
        manifest.verify()?;
    }
    Ok(manifest)
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
fn verify_deletion_manifest_for_test(
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
    for target in &preflight.targets {
        fs::remove_file(&target.absolute_path).map_err(|error| MigratorError::DeletionFailed {
            path: target.path.clone(),
            error: error.to_string(),
        })?;
    }
    build_receipt(manifest, &preflight)
}

#[cfg(test)]
fn apply_deletion_manifest_for_test(
    repository_root: &Path,
    manifest: &DeletionManifest,
) -> Result<DeletionReceipt, MigratorError> {
    let preflight = preflight(repository_root, manifest, true)?;
    for target in &preflight.targets {
        fs::remove_file(&target.absolute_path).map_err(|error| MigratorError::DeletionFailed {
            path: target.path.clone(),
            error: error.to_string(),
        })?;
    }
    build_receipt(manifest, &preflight)
}

#[derive(Serialize)]
struct DeletionManifestPayload<'a> {
    base_sha: &'a str,
    batch_plan: &'a BatchPlan,
    selected_units: &'a [MigrationUnit],
    targets: &'a [ManifestPathDeletion],
}

impl<'a> From<&'a DeletionManifest> for DeletionManifestPayload<'a> {
    fn from(manifest: &'a DeletionManifest) -> Self {
        Self {
            base_sha: &manifest.base_sha,
            batch_plan: &manifest.batch_plan,
            selected_units: &manifest.selected_units,
            targets: &manifest.targets,
        }
    }
}

fn validate_plan_authority(
    plan: &BatchPlan,
    units: &[MigrationUnit],
    allow_test_eligible: bool,
) -> Result<Vec<String>, MigratorError> {
    plan.verify()?;
    if plan.selected_unit_ids().is_empty() {
        return Err(MigratorError::ManifestIneligible);
    }
    if units.windows(2).any(|pair| pair[0].id() >= pair[1].id()) {
        return Err(MigratorError::InvalidField {
            field: "manifest selected units",
            reason: "values must be sorted and unique by unit id".to_owned(),
        });
    }
    let unit_ids: Vec<&str> = units.iter().map(MigrationUnit::id).collect();
    if unit_ids != plan.selected_unit_ids() {
        return Err(MigratorError::InvalidField {
            field: "manifest selected units",
            reason: "must exactly match the batch plan's selected unit ids".to_owned(),
        });
    }
    let unit_digests: Vec<&str> = units.iter().map(MigrationUnit::content_digest).collect();
    if unit_digests != plan.selected_unit_digests() {
        return Err(MigratorError::InvalidField {
            field: "manifest selected unit digests",
            reason: "must exactly match the batch plan's selected unit digests".to_owned(),
        });
    }

    let mut paths = BTreeSet::new();
    for unit in units {
        #[cfg(test)]
        if allow_test_eligible && unit.status() == MigrationStatus::DeletionEligible {
            unit.verify_deletion_eligible_for_test()?;
        } else {
            unit.verify()?;
        }
        #[cfg(not(test))]
        {
            let _ = allow_test_eligible;
            unit.verify()?;
        }
        if unit.base_sha() != plan.base_sha() || unit.status() != MigrationStatus::DeletionEligible
        {
            return Err(MigratorError::ManifestIneligible);
        }
        for target in &unit.spec().deletion_targets {
            match target {
                DeletionTarget::Path { path } => {
                    validate_exact_file_path(path)?;
                    paths.insert(path.clone());
                }
                DeletionTarget::Symbol { .. } => {
                    return Err(MigratorError::UnsupportedDeletionTarget(
                        "symbol".to_owned(),
                    ));
                }
            }
        }
    }
    if paths.is_empty() || paths.len() > MAX_TARGETS {
        return Err(MigratorError::InvalidField {
            field: "deletion manifest targets",
            reason: format!("must contain between 1 and {MAX_TARGETS} exact path targets"),
        });
    }
    Ok(paths.into_iter().collect())
}

fn validate_bound_targets(
    targets: &[ManifestPathDeletion],
    expected_paths: &[String],
) -> Result<(), MigratorError> {
    if targets.len() != expected_paths.len()
        || targets
            .iter()
            .map(|target| target.path.as_str())
            .ne(expected_paths.iter().map(String::as_str))
    {
        return Err(MigratorError::InvalidField {
            field: "deletion manifest targets",
            reason: "must be the exact path union from selected eligible units".to_owned(),
        });
    }
    for target in targets {
        validate_exact_file_path(&target.path)?;
        validate_digest(&target.before_content_digest, "before-content digest")?;
    }
    Ok(())
}

fn bind_targets(root: &Path, paths: &[String]) -> Result<Vec<ManifestPathDeletion>, MigratorError> {
    let mut targets = Vec::with_capacity(paths.len());
    for path in paths {
        let absolute_path = inspect_regular_file(root, path)?;
        ensure_tracked(root, path)?;
        let (before_content_digest, _) = reader_digest(fs::File::open(absolute_path)?)?;
        targets.push(ManifestPathDeletion {
            path: path.clone(),
            before_content_digest,
        });
    }
    Ok(targets)
}

struct VerifiedPreflight {
    public: DeletionPreflight,
    targets: Vec<PreflightTarget>,
}

struct PreflightTarget {
    path: String,
    absolute_path: PathBuf,
    before_content_digest: String,
    bytes: u64,
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
                path: target.path.clone(),
                expected: target.before_content_digest.clone(),
                actual,
            });
        }
        total_bytes = total_bytes
            .checked_add(byte_count)
            .ok_or(MigratorError::ScoreOverflow)?;
        targets.push(PreflightTarget {
            path: target.path.clone(),
            absolute_path,
            before_content_digest: target.before_content_digest.clone(),
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

fn verify_repository_state(
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

fn inspect_regular_file(root: &Path, path: &str) -> Result<PathBuf, MigratorError> {
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

fn ensure_tracked(root: &Path, path: &str) -> Result<(), MigratorError> {
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

fn build_receipt(
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
        preflight_digest: preflight.public.content_digest.clone(),
        base_sha: manifest.base_sha().to_owned(),
        deleted_files: preflight.public.target_count,
        deleted_bytes: preflight.public.total_bytes,
        deleted_paths,
    };
    receipt.content_digest = canonical_digest(&DeletionReceiptPayload::from(&receipt))?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::planner::plan_maximum_deletion_for_test;
    use crate::{
        DeletionBenefit, MigrationUnitKind, MigrationUnitSpec, PlanObjective, plan_maximum_deletion,
    };

    const CONTRACT_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static NEXT_REPOSITORY: AtomicU64 = AtomicU64::new(1);

    struct TestRepository {
        root: PathBuf,
    }

    impl TestRepository {
        fn new(files: &[(&str, &[u8])]) -> Self {
            let sequence = NEXT_REPOSITORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "cerebro-migrator-deletion-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            run_git(&root, &["init", "--quiet"]);
            run_git(&root, &["config", "user.name", "Cerebro Migrator Test"]);
            run_git(
                &root,
                &["config", "user.email", "cerebro-migrator@example.invalid"],
            );
            let repository = Self { root };
            for (path, bytes) in files {
                repository.write(path, bytes);
            }
            repository.commit_all("initial fixture");
            repository
        }

        fn path(&self) -> &Path {
            &self.root
        }

        fn write(&self, path: &str, bytes: &[u8]) {
            let absolute = self.root.join(path);
            if let Some(parent) = absolute.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(absolute, bytes).unwrap();
        }

        fn commit_all(&self, message: &str) {
            run_git(&self.root, &["add", "--all"]);
            run_git(&self.root, &["commit", "--quiet", "-m", message]);
        }

        fn head(&self) -> String {
            git_stdout(&self.root, &["rev-parse", "HEAD"])
        }
    }

    impl Drop for TestRepository {
        fn drop(&mut self) {
            if self.root.starts_with(std::env::temp_dir())
                && self.root.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with("cerebro-migrator-deletion-test-")
                })
            {
                fs::remove_dir_all(&self.root).unwrap();
            }
        }
    }

    #[test]
    fn applies_exact_regular_files_and_emits_bound_receipt() {
        let repository =
            TestRepository::new(&[("a.go", b"package a\n"), ("nested/b.go", b"package b\n")]);
        let manifest = manifest(&repository, &["nested/b.go", "a.go"]);

        let preflight = verify_deletion_manifest_for_test(repository.path(), &manifest).unwrap();
        assert_eq!(preflight.target_count(), 2);
        assert_eq!(preflight.total_bytes(), 20);
        assert!(repository.path().join("a.go").is_file());

        let receipt = apply_deletion_manifest_for_test(repository.path(), &manifest).unwrap();
        assert_eq!(receipt.deleted_files(), 2);
        assert_eq!(receipt.deleted_bytes(), 20);
        assert_eq!(
            receipt.deleted_paths().collect::<Vec<_>>(),
            vec!["a.go", "nested/b.go"]
        );
        assert!(!repository.path().join("a.go").exists());
        assert!(!repository.path().join("nested/b.go").exists());
        receipt.verify().unwrap();
    }

    #[test]
    fn rejects_before_content_digest_mismatch_without_deleting() {
        let repository = TestRepository::new(&[("a.go", b"package a\n")]);
        let manifest = manifest(&repository, &["a.go"]);
        run_git(
            repository.path(),
            &["update-index", "--assume-unchanged", "a.go"],
        );
        repository.write("a.go", b"changed!!\n");
        assert!(git_stdout(repository.path(), &["status", "--porcelain"]).is_empty());

        let error = apply_deletion_manifest_for_test(repository.path(), &manifest).unwrap_err();
        assert!(matches!(error, MigratorError::FileDigestMismatch { .. }));
        assert!(repository.path().join("a.go").is_file());
    }

    #[test]
    fn rejects_dirty_worktree_and_base_mismatch() {
        let dirty_repository = TestRepository::new(&[("a.go", b"package a\n")]);
        let dirty_manifest = manifest(&dirty_repository, &["a.go"]);
        dirty_repository.write("untracked.txt", b"dirty\n");
        let error =
            apply_deletion_manifest_for_test(dirty_repository.path(), &dirty_manifest).unwrap_err();
        assert_eq!(error, MigratorError::DirtyWorktree);
        assert!(dirty_repository.path().join("a.go").is_file());

        let advanced_repository = TestRepository::new(&[("a.go", b"package a\n")]);
        let stale_manifest = manifest(&advanced_repository, &["a.go"]);
        advanced_repository.write("new.go", b"package new\n");
        advanced_repository.commit_all("advance base");
        let error = verify_deletion_manifest_for_test(advanced_repository.path(), &stale_manifest)
            .unwrap_err();
        assert!(matches!(error, MigratorError::BaseShaMismatch { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_and_directory_targets() {
        use std::os::unix::fs::symlink;

        let repository = TestRepository::new(&[("real.go", b"package real\n")]);
        symlink("real.go", repository.path().join("linked.go")).unwrap();
        repository.commit_all("add symlink");
        let error = build_manifest(
            &repository,
            vec![eligible_unit(
                &repository,
                "delete/symlink",
                &["linked.go"],
                1,
            )],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MigratorError::InvalidDeletionTarget { ref reason, .. }
                if reason.contains("symbolic links")
        ));

        fs::create_dir(repository.path().join("empty-directory")).unwrap();
        let error = build_manifest(
            &repository,
            vec![eligible_unit(
                &repository,
                "delete/directory",
                &["empty-directory"],
                1,
            )],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MigratorError::InvalidDeletionTarget { ref reason, .. }
                if reason.contains("not a regular file")
        ));
    }

    #[test]
    fn failed_all_target_preflight_leaves_every_file_intact() {
        let repository = TestRepository::new(&[("a.go", b"package a\n"), ("z.go", b"package z\n")]);
        let manifest = manifest(&repository, &["a.go", "z.go"]);
        run_git(
            repository.path(),
            &["update-index", "--assume-unchanged", "z.go"],
        );
        repository.write("z.go", b"changed!!\n");
        assert!(git_stdout(repository.path(), &["status", "--porcelain"]).is_empty());

        let error = apply_deletion_manifest_for_test(repository.path(), &manifest).unwrap_err();
        assert!(matches!(error, MigratorError::FileDigestMismatch { .. }));
        assert!(repository.path().join("a.go").is_file());
        assert!(repository.path().join("z.go").is_file());
    }

    #[test]
    fn candidate_units_and_symbol_targets_cannot_mint_manifest() {
        let repository = TestRepository::new(&[("a.go", b"package a\n")]);
        let candidate = candidate_unit(&repository, "delete/candidate", &["a.go"], 1);
        let plan =
            plan_maximum_deletion(std::slice::from_ref(&candidate), PlanObjective::default())
                .unwrap();
        let error = bind_deletion_manifest(repository.path(), plan, vec![candidate]).unwrap_err();
        assert_eq!(error, MigratorError::ManifestIneligible);

        let symbol = eligible_symbol_unit(&repository);
        let plan =
            plan_maximum_deletion_for_test(std::slice::from_ref(&symbol), PlanObjective::default())
                .unwrap();
        let error =
            bind_deletion_manifest_for_test(repository.path(), plan, vec![symbol]).unwrap_err();
        assert_eq!(
            error,
            MigratorError::UnsupportedDeletionTarget("symbol".to_owned())
        );
    }

    #[test]
    fn forged_eligible_unit_json_is_rejected_by_public_verifiers() {
        let repository = TestRepository::new(&[("a.go", b"package a\n")]);
        let forged = eligible_unit(&repository, "delete/forged", &["a.go"], 1);
        let encoded = serde_json::to_vec(&forged).unwrap();
        let error = MigrationUnit::from_json_slice(&encoded).unwrap_err();
        assert!(matches!(
            error,
            MigratorError::InvalidField {
                field: "migration unit status",
                ..
            }
        ));

        let plan =
            plan_maximum_deletion_for_test(std::slice::from_ref(&forged), PlanObjective::default())
                .unwrap();
        let request_json = serde_json::to_vec(&DeletionManifestBuildRequest {
            plan,
            units: vec![forged.clone()],
        })
        .unwrap();
        let request: DeletionManifestBuildRequest = serde_json::from_slice(&request_json).unwrap();
        let error = request.bind(repository.path()).unwrap_err();
        assert!(matches!(
            error,
            MigratorError::InvalidField {
                field: "migration unit status",
                ..
            }
        ));

        let test_manifest = build_manifest(&repository, vec![forged]).unwrap();
        let error = apply_deletion_manifest(repository.path(), &test_manifest).unwrap_err();
        assert!(matches!(
            error,
            MigratorError::InvalidField {
                field: "migration unit status",
                ..
            }
        ));
        assert!(repository.path().join("a.go").is_file());
    }

    #[test]
    fn plan_and_unit_digest_substitution_cannot_mint_manifest() {
        let repository = TestRepository::new(&[("a.go", b"package a\n")]);
        let original = eligible_unit(&repository, "delete/a", &["a.go"], 1);
        let plan = plan_maximum_deletion_for_test(
            std::slice::from_ref(&original),
            PlanObjective::default(),
        )
        .unwrap();

        let substituted = eligible_unit(&repository, "delete/a", &["a.go"], 2);
        let error =
            bind_deletion_manifest_for_test(repository.path(), plan.clone(), vec![substituted])
                .unwrap_err();
        assert!(matches!(
            error,
            MigratorError::InvalidField {
                field: "manifest selected unit digests",
                ..
            }
        ));

        let mut tampered_json = serde_json::to_value(&plan).unwrap();
        tampered_json["totals"]["production_lines"] = serde_json::json!(9);
        let tampered_plan: BatchPlan = serde_json::from_value(tampered_json).unwrap();
        let error =
            bind_deletion_manifest_for_test(repository.path(), tampered_plan, vec![original])
                .unwrap_err();
        assert!(matches!(error, MigratorError::DigestMismatch { .. }));
    }

    fn manifest(repository: &TestRepository, paths: &[&str]) -> DeletionManifest {
        build_manifest(
            repository,
            vec![eligible_unit(repository, "delete/files", paths, 1)],
        )
        .unwrap()
    }

    fn build_manifest(
        repository: &TestRepository,
        units: Vec<MigrationUnit>,
    ) -> Result<DeletionManifest, MigratorError> {
        let plan = plan_maximum_deletion_for_test(&units, PlanObjective::default())?;
        bind_deletion_manifest_for_test(repository.path(), plan, units)
    }

    fn eligible_unit(
        repository: &TestRepository,
        id: &str,
        paths: &[&str],
        production_lines: u64,
    ) -> MigrationUnit {
        MigrationUnit::bind_deletion_eligible_for_test(unit_spec(
            repository,
            id,
            paths,
            production_lines,
            MigrationStatus::DeletionEligible,
        ))
        .unwrap()
    }

    fn candidate_unit(
        repository: &TestRepository,
        id: &str,
        paths: &[&str],
        production_lines: u64,
    ) -> MigrationUnit {
        MigrationUnit::bind(unit_spec(
            repository,
            id,
            paths,
            production_lines,
            MigrationStatus::Candidate,
        ))
        .unwrap()
    }

    fn unit_spec(
        repository: &TestRepository,
        id: &str,
        paths: &[&str],
        production_lines: u64,
        status: MigrationStatus,
    ) -> MigrationUnitSpec {
        MigrationUnitSpec {
            id: id.to_owned(),
            kind: MigrationUnitKind::GoPackageComponent,
            base_sha: repository.head(),
            go_owners: vec![format!("package:{id}")],
            production_entrypoints: vec!["cmd/cerebro".to_owned()],
            rust_operation: format!("replace/{id}"),
            contract_digest: CONTRACT_DIGEST.to_owned(),
            prerequisites: Vec::new(),
            authority_gates: vec!["single-writer".to_owned()],
            required_receipts: vec!["parity".to_owned()],
            deletion_targets: paths
                .iter()
                .map(|path| DeletionTarget::Path {
                    path: (*path).to_owned(),
                })
                .collect(),
            benefit: DeletionBenefit {
                production_lines,
                ..DeletionBenefit::default()
            },
            effort: 0,
            status,
            blockers: Vec::new(),
        }
    }

    fn eligible_symbol_unit(repository: &TestRepository) -> MigrationUnit {
        let mut spec = unit_spec(
            repository,
            "delete/symbol",
            &[],
            1,
            MigrationStatus::DeletionEligible,
        );
        spec.deletion_targets = vec![DeletionTarget::Symbol {
            path: "a.go".to_owned(),
            symbol: "OldWriter".to_owned(),
            expected_before_digest: CONTRACT_DIGEST.to_owned(),
        }];
        MigrationUnit::bind_deletion_eligible_for_test(spec).unwrap()
    }

    fn run_git(root: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_stdout(root: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}
