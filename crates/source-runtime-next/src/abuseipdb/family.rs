use std::str::FromStr;

use super::AbuseIpDbError;

/// Closed AbuseIPDB source-catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AbuseIpDbFamily {
    /// Paginated report history for one configured IP address.
    Reports,
    /// One bounded blacklist snapshot.
    IpAddresses,
}

impl AbuseIpDbFamily {
    /// Every provider-declared family in catalog order.
    pub const ALL: [Self; 2] = [Self::Reports, Self::IpAddresses];

    /// Exact catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reports => "reports",
            Self::IpAddresses => "ip_addresses",
        }
    }

    /// Exact admitted event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Reports => "abuseipdb.reports",
            Self::IpAddresses => "abuseipdb.ip_addresses",
        }
    }

    /// Exact admitted event schema.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Reports => "abuseipdb/reports/v1",
            Self::IpAddresses => "abuseipdb/ip_addresses/v1",
        }
    }

    /// Provider-relative operation path.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Reports => "/reports",
            Self::IpAddresses => "/blacklist",
        }
    }
}

impl FromStr for AbuseIpDbFamily {
    type Err = AbuseIpDbError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AbuseIpDbError::InvalidFamily)
    }
}
