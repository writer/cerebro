use std::{error::Error, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    Empty {
        kind: &'static str,
    },
    TooLong {
        kind: &'static str,
        max_bytes: usize,
    },
    SurroundingWhitespace {
        kind: &'static str,
    },
    ControlCharacter {
        kind: &'static str,
    },
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { kind } => write!(formatter, "{kind} is required"),
            Self::TooLong { kind, max_bytes } => {
                write!(formatter, "{kind} exceeds {max_bytes} bytes")
            }
            Self::SurroundingWhitespace { kind } => {
                write!(formatter, "{kind} contains surrounding whitespace")
            }
            Self::ControlCharacter { kind } => {
                write!(formatter, "{kind} contains a control character")
            }
        }
    }
}

impl Error for IdentifierError {}

macro_rules! identifier {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, IdentifierError> {
                validate_identifier(value.into(), $kind).map(Self)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

identifier!(TenantId, "tenant id");
identifier!(MandateId, "mandate id");
identifier!(MissionId, "mission id");
identifier!(ActorId, "actor id");
identifier!(GrantId, "grant id");
identifier!(DecisionId, "decision id");
identifier!(VerificationId, "verification id");
identifier!(RequestId, "request id");

fn validate_identifier(value: String, kind: &'static str) -> Result<String, IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty { kind });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(IdentifierError::TooLong {
            kind,
            max_bytes: MAX_IDENTIFIER_BYTES,
        });
    }
    if value.trim() != value {
        return Err(IdentifierError::SurroundingWhitespace { kind });
    }
    if value.chars().any(char::is_control) {
        return Err(IdentifierError::ControlCharacter { kind });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_preserve_exact_valid_values() {
        let tenant = TenantId::parse("tenant/acme").expect("valid tenant id");
        let mandate = MandateId::parse("mandate:access-removal").expect("valid mandate id");

        assert_eq!(tenant.as_str(), "tenant/acme");
        assert_eq!(mandate.as_str(), "mandate:access-removal");
    }

    #[test]
    fn identifiers_reject_ambiguous_or_unsafe_values() {
        assert!(matches!(
            MissionId::parse(" mission-1"),
            Err(IdentifierError::SurroundingWhitespace { .. })
        ));
        assert!(matches!(
            ActorId::parse("actor\nadmin"),
            Err(IdentifierError::ControlCharacter { .. })
        ));
        assert!(matches!(
            TenantId::parse(""),
            Err(IdentifierError::Empty { .. })
        ));
    }

    #[test]
    fn identifiers_enforce_a_bounded_wire_size() {
        let oversized = "a".repeat(MAX_IDENTIFIER_BYTES + 1);
        assert!(matches!(
            MissionId::parse(oversized),
            Err(IdentifierError::TooLong { .. })
        ));
    }
}
