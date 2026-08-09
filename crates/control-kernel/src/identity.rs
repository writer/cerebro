use std::{error::Error, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

const MAX_IDENTIFIER_BYTES: usize = 256;

/// Reason a control-kernel identifier was rejected at its construction
/// boundary.
///
/// Identifiers remain opaque strings after validation: the kernel enforces a
/// bounded, unambiguous wire representation without imposing provider- or
/// deployment-specific syntax.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    /// No identifier bytes were supplied.
    Empty {
        /// Human-readable identifier class used in the error message.
        kind: &'static str,
    },
    /// The UTF-8 representation exceeds the kernel's wire-size bound.
    TooLong {
        /// Human-readable identifier class used in the error message.
        kind: &'static str,
        /// Maximum accepted UTF-8 byte length.
        max_bytes: usize,
    },
    /// The value would change if leading or trailing whitespace were removed.
    SurroundingWhitespace {
        /// Human-readable identifier class used in the error message.
        kind: &'static str,
    },
    /// The value contains a Unicode control character.
    ControlCharacter {
        /// Human-readable identifier class used in the error message.
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
    ($name:ident, $kind:literal, $doc:literal) => {
        #[doc = $doc]
        ///
        /// The value is serialized transparently as its validated string and
        /// must be created through [`Self::parse`] or [`std::str::FromStr`].
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates and constructs this identifier without normalizing
            /// the caller's bytes.
            pub fn parse(value: impl Into<String>) -> Result<Self, IdentifierError> {
                validate_identifier(value.into(), $kind).map(Self)
            }

            /// Returns the exact validated wire value.
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

identifier!(
    TenantId,
    "tenant id",
    "Stable tenant boundary for every control-kernel record."
);
identifier!(
    MandateId,
    "mandate id",
    "Stable identity of an operator-approved mandate."
);
identifier!(
    MissionId,
    "mission id",
    "Stable identity of one durable mission lifecycle."
);
identifier!(
    BeliefId,
    "belief id",
    "Stable identity of one revisable belief record."
);
identifier!(
    PlanId,
    "plan id",
    "Stable identity shared by all revisions of one plan."
);
identifier!(
    CommitmentId,
    "commitment id",
    "Stable identity of one plan-bound commitment."
);
identifier!(
    WakeConditionId,
    "wake condition id",
    "Stable identity of one durable wake predicate."
);
identifier!(
    ConversationId,
    "conversation id",
    "Stable identity of one ordered conversation."
);
identifier!(
    ActorId,
    "actor id",
    "Stable identity of a human or machine actor."
);
identifier!(
    GrantId,
    "grant id",
    "Stable identity of a bounded capability grant."
);
identifier!(
    DecisionId,
    "decision id",
    "Stable identity of an authorization decision."
);
identifier!(
    VerificationId,
    "verification id",
    "Stable identity of an independent verification receipt."
);
identifier!(
    RequestId,
    "request id",
    "Stable identity of an idempotent protocol request."
);

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
