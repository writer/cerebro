use std::str::FromStr;

use super::AcunetixError;

/// Closed Acunetix catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AcunetixFamily {
    /// Generated reports.
    Reports,
    /// Scanning policy profiles.
    ScanningProfiles,
    /// Scan runs.
    Scans,
    /// Scan targets.
    Targets,
    /// Detected vulnerabilities.
    Vulnerabilities,
}

impl AcunetixFamily {
    /// Every provider-declared family.
    pub const ALL: [Self; 5] = [
        Self::Reports,
        Self::ScanningProfiles,
        Self::Scans,
        Self::Targets,
        Self::Vulnerabilities,
    ];

    /// Exact catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reports => "reports",
            Self::ScanningProfiles => "scanning_profiles",
            Self::Scans => "scans",
            Self::Targets => "targets",
            Self::Vulnerabilities => "vulnerabilities",
        }
    }

    /// Exact provider path relative to `/api/v1`.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Reports => "/reports",
            Self::ScanningProfiles => "/scanning_profiles",
            Self::Scans => "/scans",
            Self::Targets => "/targets",
            Self::Vulnerabilities => "/vulnerabilities",
        }
    }

    /// Provider response-array key.
    pub const fn response_key(self) -> &'static str {
        self.as_str()
    }

    /// Stable provider identity field.
    pub const fn id_field(self) -> &'static str {
        match self {
            Self::Reports => "report_id",
            Self::ScanningProfiles => "profile_id",
            Self::Scans => "scan_id",
            Self::Targets => "target_id",
            Self::Vulnerabilities => "vuln_id",
        }
    }

    /// Exact event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Reports => "acunetix.reports",
            Self::ScanningProfiles => "acunetix.scanning_profiles",
            Self::Scans => "acunetix.scans",
            Self::Targets => "acunetix.targets",
            Self::Vulnerabilities => "acunetix.vulnerabilities",
        }
    }

    /// Exact schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Reports => "acunetix/reports/v1",
            Self::ScanningProfiles => "acunetix/scanning_profiles/v1",
            Self::Scans => "acunetix/scans/v1",
            Self::Targets => "acunetix/targets/v1",
            Self::Vulnerabilities => "acunetix/vulnerabilities/v1",
        }
    }
}

impl FromStr for AcunetixFamily {
    type Err = AcunetixError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AcunetixError::InvalidFamily)
    }
}
