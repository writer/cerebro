use std::str::FromStr;

use super::ArchetypeError;

/// One Archetype source-catalog family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchetypeFamily {
    /// Scan lifecycle records only.
    Scan,
    /// Scan lifecycle, vulnerability, and repository knowledge records.
    Vulnerability,
}

impl ArchetypeFamily {
    /// Return the source-catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Vulnerability => "vulnerability",
        }
    }
}

impl FromStr for ArchetypeFamily {
    type Err = ArchetypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "scan" => Ok(Self::Scan),
            "vulnerability" => Ok(Self::Vulnerability),
            _ => Err(ArchetypeError::InvalidFamily),
        }
    }
}
/// Availability of the vulnerability fanout for one emitted scan record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VulnerabilityCollectionState {
    /// The scan-only family did not request vulnerabilities.
    NotRequested,
    /// The provider reported that retained scan results are unavailable.
    Unavailable,
    /// The vulnerability request completed successfully.
    Complete,
}

impl VulnerabilityCollectionState {
    /// Return the Go-compatible scan attribute value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::Unavailable => "unavailable",
            Self::Complete => "complete",
        }
    }
}
