use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    CatalogDecode {
        path: PathBuf,
        message: String,
    },
    Catalog(CatalogError),
    Json(serde_json::Error),
    Formatter {
        operation: &'static str,
        source: io::Error,
    },
    FormatterInputUnavailable,
    FormatterFailed {
        stderr: String,
    },
    FileTooLarge {
        label: &'static str,
        limit: usize,
    },
    SymlinkNotAllowed,
    MissingParent(PathBuf),
    UnsupportedPlatform,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CatalogError {
    UnsupportedVersion(String),
    NoActions,
    RequiredField {
        index: usize,
        field: &'static str,
    },
    InvalidGoIdentifier {
        index: usize,
        field: &'static str,
        value: String,
    },
    DuplicateActionId(String),
    DuplicateConstName(String),
    ConflictingConstant {
        action_id: String,
        field: &'static str,
        constant: String,
        prior: String,
        value: String,
    },
    UnknownReversibleAction {
        action_id: String,
        reversible_by: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
            Self::CatalogDecode { path, message } => {
                write!(formatter, "decode catalog {}: {message}", path.display())
            }
            Self::Catalog(error) => error.fmt(formatter),
            Self::Json(error) => write!(formatter, "quote Go string: {error}"),
            Self::Formatter { operation, source } => {
                write!(formatter, "{operation} gofmt: {source}")
            }
            Self::FormatterInputUnavailable => formatter.write_str("open gofmt stdin"),
            Self::FormatterFailed { stderr } => {
                write!(formatter, "format generated Go: {stderr}")
            }
            Self::FileTooLarge { label, limit } => {
                write!(formatter, "{label} exceeds {limit} bytes")
            }
            Self::SymlinkNotAllowed => {
                formatter.write_str("symlinked generated graph action files are not allowed")
            }
            Self::MissingParent(path) => {
                write!(formatter, "{} has no parent directory", path.display())
            }
            Self::UnsupportedPlatform => {
                formatter.write_str("graph action generation requires Unix file semantics")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io { source, .. } | Self::Formatter { source, .. } => Some(source),
            Self::Json(source) => Some(source),
            _ => None,
        }
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported catalog version {version:?}")
            }
            Self::NoActions => formatter.write_str("catalog has no actions"),
            Self::RequiredField { index, field } => {
                write!(formatter, "actions[{index}].{field} is required")
            }
            Self::InvalidGoIdentifier {
                index,
                field,
                value,
            } => write!(
                formatter,
                "actions[{index}].{field} = {value:?} is not a Go identifier"
            ),
            Self::DuplicateActionId(id) => write!(formatter, "duplicate action id {id:?}"),
            Self::DuplicateConstName(name) => {
                write!(formatter, "duplicate action const_name {name:?}")
            }
            Self::ConflictingConstant {
                action_id,
                field,
                constant,
                prior,
                value,
            } => write!(
                formatter,
                "action {action_id:?}: {field} {constant:?} maps to both {prior:?} and {value:?}"
            ),
            Self::UnknownReversibleAction {
                action_id,
                reversible_by,
            } => write!(
                formatter,
                "action {action_id:?} reversible_by references unknown action {reversible_by:?}"
            ),
        }
    }
}

impl StdError for CatalogError {}

impl From<CatalogError> for Error {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}
