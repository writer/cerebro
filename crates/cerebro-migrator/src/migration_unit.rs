use serde::{Deserialize, Serialize};

use crate::MigratorError;
use crate::digest::canonical_digest;
use crate::validation::{
    validate_digest, validate_exact_file_path, validate_git_sha, validate_identifier,
};

/// Current qualification state of a migration unit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    /// The unit has a typed reason that prevents inclusion in a batch.
    Blocked,
    /// A Rust replacement and its evidence still need to be produced.
    Candidate,
    /// Replacement code has been generated but is not yet qualified.
    Generated,
    /// Required parity and authority evidence has been collected.
    Qualified,
    /// Every gate required by the later deletion executor is satisfied.
    DeletionEligible,
}

/// Closed behavior class represented by a migration unit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationUnitKind {
    /// A reusable Rust runtime or contract capability.
    RuntimeCapability,
    /// One source and record family.
    SourceFamily,
    /// One source-to-graph projection family.
    Projection,
    /// One bounded graph query behavior.
    GraphQuery,
    /// One finding matcher and lifecycle contract.
    FindingRule,
    /// One authenticated API route.
    ApiRoute,
    /// One CLI command contract.
    CliCommand,
    /// One complete Go package deletion component.
    GoPackageComponent,
}

/// An exact path or symbol that a future qualified executor may delete.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeletionTarget {
    /// An exact repository-relative file path. Directories and globs are invalid.
    Path {
        /// Exact repository-relative file path.
        path: String,
    },
    /// A symbol with a digest of the exact expected pre-edit bytes.
    Symbol {
        /// Exact repository-relative file path containing the symbol.
        path: String,
        /// AST-addressable declaration name.
        symbol: String,
        /// Digest of the exact bytes expected before the edit.
        expected_before_digest: String,
    },
}

/// Measurable Go runtime material removed when a unit is completed.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionBenefit {
    /// Production Go lines removed.
    pub production_lines: u64,
    /// Go test lines removed.
    pub test_lines: u64,
    /// Complete Go packages removed from production reachability.
    pub packages: u64,
    /// Deployable Go entry points removed.
    pub runtime_entrypoints: u64,
}

/// Unbound input used to construct a content-addressed migration unit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationUnitSpec {
    /// Stable semantic identity, such as `source/openai/models`.
    pub id: String,
    /// Closed migration behavior class.
    pub kind: MigrationUnitKind,
    /// Exact repository commit on which ownership and deletion facts were measured.
    pub base_sha: String,
    /// Canonical package, file, or symbol owners on the Go path.
    #[serde(default)]
    pub go_owners: Vec<String>,
    /// Production entry points that can reach the behavior.
    #[serde(default)]
    pub production_entrypoints: Vec<String>,
    /// Stable Rust operation intended to replace the Go behavior.
    pub rust_operation: String,
    /// Digest of the portable behavior contract.
    pub contract_digest: String,
    /// Migration unit identifiers required by this unit.
    #[serde(default)]
    pub prerequisites: Vec<String>,
    /// Authority invariants that must be proved before deletion.
    #[serde(default)]
    pub authority_gates: Vec<String>,
    /// Receipt classes required before deletion.
    #[serde(default)]
    pub required_receipts: Vec<String>,
    /// Exact future deletion targets; globs and directories are rejected.
    #[serde(default)]
    pub deletion_targets: Vec<DeletionTarget>,
    /// Go material removed by this unit.
    #[serde(default)]
    pub benefit: DeletionBenefit,
    /// Deterministic relative implementation/evidence cost.
    #[serde(default)]
    pub effort: u64,
    /// Current migration state.
    pub status: MigrationStatus,
    /// Typed reasons preventing progress; required when status is blocked.
    #[serde(default)]
    pub blockers: Vec<String>,
}

/// Immutable, normalized, content-addressed migration-unit document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationUnit {
    schema_version: String,
    content_digest: String,
    unit: MigrationUnitSpec,
}

impl MigrationUnit {
    /// Validates, normalizes, and content-binds a migration unit.
    ///
    /// `deletion_eligible` is intentionally rejected here: raw JSON status text
    /// is not qualification evidence. A future qualification command must verify
    /// closed receipt documents before it can issue an eligible bound unit.
    pub fn bind(unit: MigrationUnitSpec) -> Result<Self, MigratorError> {
        if unit.status == MigrationStatus::DeletionEligible {
            return Err(MigratorError::InvalidField {
                field: "migration unit status",
                reason: "deletion_eligible requires a receipt-verifying qualification boundary"
                    .to_owned(),
            });
        }
        Self::bind_validated(unit)
    }

    #[cfg(test)]
    pub(crate) fn bind_deletion_eligible_for_test(
        unit: MigrationUnitSpec,
    ) -> Result<Self, MigratorError> {
        debug_assert_eq!(unit.status, MigrationStatus::DeletionEligible);
        Self::bind_validated(unit)
    }

    fn bind_validated(mut unit: MigrationUnitSpec) -> Result<Self, MigratorError> {
        normalize_spec(&mut unit);
        validate_spec(&unit)?;
        let content_digest = canonical_digest(&unit)?;
        Ok(Self {
            schema_version: "cerebro.migrator.migration-unit/v1".to_owned(),
            content_digest,
            unit,
        })
    }

    /// Parses and verifies a previously bound migration-unit document.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, MigratorError> {
        let document: Self = serde_json::from_slice(bytes)?;
        document.verify()?;
        Ok(document)
    }

    /// Recomputes all invariants and the content digest.
    pub fn verify(&self) -> Result<(), MigratorError> {
        if self.unit.status == MigrationStatus::DeletionEligible {
            return Err(MigratorError::InvalidField {
                field: "migration unit status",
                reason: "deletion_eligible requires a receipt-verifying qualification boundary"
                    .to_owned(),
            });
        }
        self.verify_bound_payload()
    }

    #[cfg(test)]
    pub(crate) fn verify_deletion_eligible_for_test(&self) -> Result<(), MigratorError> {
        debug_assert_eq!(self.unit.status, MigrationStatus::DeletionEligible);
        self.verify_bound_payload()
    }

    fn verify_bound_payload(&self) -> Result<(), MigratorError> {
        if self.schema_version != "cerebro.migrator.migration-unit/v1" {
            return Err(MigratorError::InvalidField {
                field: "migration unit schema_version",
                reason: format!("unsupported value {}", self.schema_version),
            });
        }
        validate_spec(&self.unit)?;
        let actual = canonical_digest(&self.unit)?;
        if actual != self.content_digest {
            return Err(MigratorError::DigestMismatch {
                expected: self.content_digest.clone(),
                actual,
            });
        }
        Ok(())
    }

    /// Returns the stable semantic unit identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.unit.id
    }

    /// Returns the exact repository revision on which the unit is based.
    #[must_use]
    pub fn base_sha(&self) -> &str {
        &self.unit.base_sha
    }

    /// Returns the unit's current qualification state.
    #[must_use]
    pub fn status(&self) -> MigrationStatus {
        self.unit.status
    }

    /// Returns prerequisite migration-unit identifiers in lexical order.
    #[must_use]
    pub fn prerequisites(&self) -> &[String] {
        &self.unit.prerequisites
    }

    /// Returns typed blocker reason codes.
    #[must_use]
    pub fn blockers(&self) -> &[String] {
        &self.unit.blockers
    }

    /// Returns the measured Go deletion benefit.
    #[must_use]
    pub fn benefit(&self) -> DeletionBenefit {
        self.unit.benefit
    }

    /// Returns the estimated relative migration effort.
    #[must_use]
    pub fn effort(&self) -> u64 {
        self.unit.effort
    }

    /// Returns the canonical digest binding the normalized unit payload.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Returns the normalized unit payload.
    #[must_use]
    pub fn spec(&self) -> &MigrationUnitSpec {
        &self.unit
    }
}

fn normalize_spec(unit: &mut MigrationUnitSpec) {
    sort_dedup(&mut unit.go_owners);
    sort_dedup(&mut unit.production_entrypoints);
    sort_dedup(&mut unit.prerequisites);
    sort_dedup(&mut unit.authority_gates);
    sort_dedup(&mut unit.required_receipts);
    sort_dedup(&mut unit.blockers);
    unit.deletion_targets.sort();
    unit.deletion_targets.dedup();
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn validate_spec(unit: &MigrationUnitSpec) -> Result<(), MigratorError> {
    validate_identifier(&unit.id, "migration unit id")?;
    validate_git_sha(&unit.base_sha, "base SHA")?;
    validate_digest(&unit.contract_digest, "contract digest")?;
    validate_identifier(&unit.rust_operation, "Rust operation")?;
    validate_sorted_unique(&unit.go_owners, "Go owners")?;
    validate_sorted_unique(&unit.production_entrypoints, "production entrypoints")?;
    validate_sorted_unique(&unit.prerequisites, "prerequisites")?;
    validate_sorted_unique(&unit.authority_gates, "authority gates")?;
    validate_sorted_unique(&unit.required_receipts, "required receipts")?;
    validate_sorted_unique(&unit.blockers, "blockers")?;
    if unit.status == MigrationStatus::Blocked && unit.blockers.is_empty() {
        return Err(MigratorError::InvalidField {
            field: "blockers",
            reason: "blocked units require at least one reason code".to_owned(),
        });
    }
    if unit.status != MigrationStatus::Blocked && !unit.blockers.is_empty() {
        return Err(MigratorError::InvalidField {
            field: "blockers",
            reason: "only blocked units may carry blocker reasons".to_owned(),
        });
    }
    if unit.prerequisites.iter().any(|item| item == &unit.id) {
        return Err(MigratorError::InvalidField {
            field: "prerequisites",
            reason: "a unit cannot require itself".to_owned(),
        });
    }
    for prerequisite in &unit.prerequisites {
        validate_identifier(prerequisite, "prerequisite id")?;
    }
    for target in &unit.deletion_targets {
        validate_deletion_target(target)?;
    }
    if unit
        .deletion_targets
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(MigratorError::InvalidField {
            field: "deletion targets",
            reason: "values must be sorted and unique".to_owned(),
        });
    }
    Ok(())
}

fn validate_deletion_target(target: &DeletionTarget) -> Result<(), MigratorError> {
    let (path, symbol_digest) = match target {
        DeletionTarget::Path { path } => (path, None),
        DeletionTarget::Symbol {
            path,
            symbol,
            expected_before_digest,
        } => {
            validate_identifier(symbol, "deletion symbol")?;
            (path, Some(expected_before_digest))
        }
    };
    validate_exact_file_path(path)?;
    if let Some(digest) = symbol_digest {
        validate_digest(digest, "expected-before digest")?;
    }
    Ok(())
}

fn validate_sorted_unique(values: &[String], field: &'static str) -> Result<(), MigratorError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(MigratorError::InvalidField {
            field,
            reason: "values must be sorted and unique".to_owned(),
        });
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(MigratorError::InvalidField {
            field,
            reason: "values must not be empty".to_owned(),
        });
    }
    Ok(())
}
