use std::error::Error;
use std::fmt;

/// A fail-closed discovery, schema, or planning error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigratorError {
    /// Input or output could not be read or written.
    Io(String),
    /// JSON input did not match the closed schema.
    Json(String),
    /// Canonical JSON could not be produced.
    Canonicalization(String),
    /// A schema field violates an invariant.
    InvalidField {
        /// Closed schema field that failed validation.
        field: &'static str,
        /// Stable explanation of the rejected value.
        reason: String,
    },
    /// A content-bound document changed after it was bound.
    DigestMismatch {
        /// Digest stored in the content-bound document.
        expected: String,
        /// Digest computed from the received payload.
        actual: String,
    },
    /// The Go package stream contained the same import path more than once.
    DuplicatePackage(String),
    /// `go list` reported a package loading error.
    GoListPackage {
        /// Import path that failed to load.
        package: String,
        /// Error text emitted by the Go tool.
        error: String,
    },
    /// A migration request declared the same unit identifier more than once.
    DuplicateUnit(String),
    /// A migration unit references a prerequisite absent from the request.
    MissingPrerequisite {
        /// Unit containing the invalid prerequisite edge.
        unit: String,
        /// Referenced unit that was absent from the request.
        prerequisite: String,
    },
    /// Units from different repository revisions were mixed in one plan.
    MixedBaseSha {
        /// Base revision established by the first canonical unit.
        expected: String,
        /// Different base revision found on another unit.
        actual: String,
    },
    /// Arithmetic exceeded the bounded planning representation.
    ScoreOverflow,
    /// A Git command required for repository-state verification failed.
    GitCommand {
        /// Stable operation name, such as `resolve-head`.
        operation: &'static str,
        /// Bounded command error text.
        error: String,
    },
    /// The requested repository root was not the checkout root.
    RepositoryRootMismatch {
        /// Canonical root supplied to the migrator.
        requested: String,
        /// Canonical root reported by Git.
        actual: String,
    },
    /// The checkout contains a tracked or untracked change before apply.
    DirtyWorktree,
    /// The manifest does not target the checkout's exact current commit.
    BaseShaMismatch {
        /// Commit bound into the manifest.
        expected: String,
        /// Current checkout commit.
        actual: String,
    },
    /// Apply was requested for a manifest that is not deletion-eligible.
    ManifestIneligible,
    /// A target class is intentionally unsupported by the current executor.
    UnsupportedDeletionTarget(String),
    /// A target does not resolve to an ordinary tracked file inside the checkout.
    InvalidDeletionTarget {
        /// Exact repository-relative target path.
        path: String,
        /// Stable reason the target was rejected.
        reason: String,
    },
    /// A target's current bytes do not match the manifest.
    FileDigestMismatch {
        /// Exact repository-relative target path.
        path: String,
        /// Digest bound into the manifest.
        expected: String,
        /// Digest computed during preflight.
        actual: String,
    },
    /// A preflighted exact file could not be removed.
    DeletionFailed {
        /// Exact repository-relative target path.
        path: String,
        /// Operating-system error returned by `remove_file`.
        error: String,
    },
}

impl fmt::Display for MigratorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "JSON decoding failed: {error}"),
            Self::Canonicalization(error) => {
                write!(formatter, "canonical JSON encoding failed: {error}")
            }
            Self::InvalidField { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "content digest mismatch: expected {expected}, computed {actual}"
            ),
            Self::DuplicatePackage(package) => {
                write!(formatter, "duplicate Go package {package}")
            }
            Self::GoListPackage { package, error } => {
                write!(formatter, "go list failed for {package}: {error}")
            }
            Self::DuplicateUnit(unit) => write!(formatter, "duplicate migration unit {unit}"),
            Self::MissingPrerequisite { unit, prerequisite } => write!(
                formatter,
                "migration unit {unit} requires missing prerequisite {prerequisite}"
            ),
            Self::MixedBaseSha { expected, actual } => write!(
                formatter,
                "migration units mix base revisions {expected} and {actual}"
            ),
            Self::ScoreOverflow => write!(formatter, "migration objective score overflowed"),
            Self::GitCommand { operation, error } => {
                write!(formatter, "Git operation {operation} failed: {error}")
            }
            Self::RepositoryRootMismatch { requested, actual } => write!(
                formatter,
                "requested repository root {requested} does not match Git root {actual}"
            ),
            Self::DirtyWorktree => write!(formatter, "repository worktree is not clean"),
            Self::BaseShaMismatch { expected, actual } => write!(
                formatter,
                "manifest base commit {expected} does not match checkout HEAD {actual}"
            ),
            Self::ManifestIneligible => {
                write!(formatter, "deletion manifest is not deletion-eligible")
            }
            Self::UnsupportedDeletionTarget(target) => {
                write!(formatter, "unsupported deletion target class {target}")
            }
            Self::InvalidDeletionTarget { path, reason } => {
                write!(formatter, "invalid deletion target {path}: {reason}")
            }
            Self::FileDigestMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "deletion target {path} digest mismatch: expected {expected}, computed {actual}"
            ),
            Self::DeletionFailed { path, error } => {
                write!(formatter, "failed to delete exact file {path}: {error}")
            }
        }
    }
}

impl Error for MigratorError {}

impl From<std::io::Error> for MigratorError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for MigratorError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::MigratorError;

    #[test]
    fn operator_errors_have_stable_actionable_messages() {
        let cases = [
            (
                MigratorError::Io("disk full".to_owned()),
                "I/O failed: disk full",
            ),
            (
                MigratorError::Json("bad token".to_owned()),
                "JSON decoding failed: bad token",
            ),
            (
                MigratorError::Canonicalization("unsupported value".to_owned()),
                "canonical JSON encoding failed: unsupported value",
            ),
            (
                MigratorError::InvalidField {
                    field: "unit id",
                    reason: "must not be empty".to_owned(),
                },
                "invalid unit id: must not be empty",
            ),
            (
                MigratorError::DigestMismatch {
                    expected: "sha256:expected".to_owned(),
                    actual: "sha256:actual".to_owned(),
                },
                "content digest mismatch: expected sha256:expected, computed sha256:actual",
            ),
            (
                MigratorError::DuplicatePackage("example/pkg".to_owned()),
                "duplicate Go package example/pkg",
            ),
            (
                MigratorError::GoListPackage {
                    package: "example/pkg".to_owned(),
                    error: "not found".to_owned(),
                },
                "go list failed for example/pkg: not found",
            ),
            (
                MigratorError::DuplicateUnit("source/example/items".to_owned()),
                "duplicate migration unit source/example/items",
            ),
            (
                MigratorError::MissingPrerequisite {
                    unit: "source/example/items".to_owned(),
                    prerequisite: "runtime/http".to_owned(),
                },
                "migration unit source/example/items requires missing prerequisite runtime/http",
            ),
            (
                MigratorError::MixedBaseSha {
                    expected: "aaaa".to_owned(),
                    actual: "bbbb".to_owned(),
                },
                "migration units mix base revisions aaaa and bbbb",
            ),
            (
                MigratorError::ScoreOverflow,
                "migration objective score overflowed",
            ),
            (
                MigratorError::GitCommand {
                    operation: "resolve-head",
                    error: "missing ref".to_owned(),
                },
                "Git operation resolve-head failed: missing ref",
            ),
            (
                MigratorError::RepositoryRootMismatch {
                    requested: "/requested".to_owned(),
                    actual: "/actual".to_owned(),
                },
                "requested repository root /requested does not match Git root /actual",
            ),
            (
                MigratorError::DirtyWorktree,
                "repository worktree is not clean",
            ),
            (
                MigratorError::BaseShaMismatch {
                    expected: "aaaa".to_owned(),
                    actual: "bbbb".to_owned(),
                },
                "manifest base commit aaaa does not match checkout HEAD bbbb",
            ),
            (
                MigratorError::ManifestIneligible,
                "deletion manifest is not deletion-eligible",
            ),
            (
                MigratorError::UnsupportedDeletionTarget("symbol".to_owned()),
                "unsupported deletion target class symbol",
            ),
            (
                MigratorError::InvalidDeletionTarget {
                    path: "internal/link.go".to_owned(),
                    reason: "symbolic link".to_owned(),
                },
                "invalid deletion target internal/link.go: symbolic link",
            ),
            (
                MigratorError::FileDigestMismatch {
                    path: "internal/source.go".to_owned(),
                    expected: "sha256:expected".to_owned(),
                    actual: "sha256:actual".to_owned(),
                },
                "deletion target internal/source.go digest mismatch: expected sha256:expected, computed sha256:actual",
            ),
            (
                MigratorError::DeletionFailed {
                    path: "internal/source.go".to_owned(),
                    error: "permission denied".to_owned(),
                },
                "failed to delete exact file internal/source.go: permission denied",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn dependency_errors_preserve_their_bounded_messages() {
        let io_error: MigratorError = std::io::Error::other("read failed").into();
        assert_eq!(io_error, MigratorError::Io("read failed".to_owned()));

        let json_error = serde_json::from_slice::<serde_json::Value>(b"{").unwrap_err();
        let expected = json_error.to_string();
        let migrator_error: MigratorError = json_error.into();
        assert_eq!(migrator_error, MigratorError::Json(expected));
    }
}
