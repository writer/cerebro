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
