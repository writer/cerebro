use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::repository::{ensure_tracked, inspect_regular_file, verify_repository_state};
use crate::digest::{canonical_digest, reader_digest};
use crate::validation::{validate_digest, validate_exact_file_path, validate_git_sha};
use crate::{BatchPlan, DeletionTarget, MigrationStatus, MigrationUnit, MigratorError};

const MANIFEST_SCHEMA: &str = "cerebro.migrator.deletion-manifest/v2";
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
    pub(super) fn verify_for_test(&self) -> Result<(), MigratorError> {
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
pub(super) fn bind_deletion_manifest_for_test(
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
