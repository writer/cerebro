use std::{fmt, str::FromStr};

use super::DigitalOceanError;

/// Closed DigitalOcean source-family set.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DigitalOceanFamily {
    /// Compute droplets.
    Droplets,
    /// Virtual private clouds.
    Vpcs,
    /// Cloud firewalls.
    Firewalls,
}

impl DigitalOceanFamily {
    /// Every family admitted by the DigitalOcean source catalog.
    pub const ALL: [Self; 3] = [Self::Droplets, Self::Vpcs, Self::Firewalls];

    /// Source catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Droplets => "droplets",
            Self::Vpcs => "vpcs",
            Self::Firewalls => "firewalls",
        }
    }

    /// Exact DigitalOcean v2 list path.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Droplets => "/v2/droplets",
            Self::Vpcs => "/v2/vpcs",
            Self::Firewalls => "/v2/firewalls",
        }
    }

    /// Exact append-log event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Droplets => "digitalocean.droplets",
            Self::Vpcs => "digitalocean.vpcs",
            Self::Firewalls => "digitalocean.firewalls",
        }
    }

    /// Exact event schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Droplets => "digitalocean/droplets/v1",
            Self::Vpcs => "digitalocean/vpcs/v1",
            Self::Firewalls => "digitalocean/firewalls/v1",
        }
    }

    pub(super) const fn resource_type(self) -> &'static str {
        match self {
            Self::Droplets => "droplet",
            Self::Vpcs => "vpc",
            Self::Firewalls => "firewall",
        }
    }

    pub(super) const fn urn_kind(self) -> &'static str {
        match self {
            Self::Droplets => "digitalocean_droplets",
            Self::Vpcs => "digitalocean_vpcs",
            Self::Firewalls => "digitalocean_firewalls",
        }
    }
}

impl fmt::Display for DigitalOceanFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DigitalOceanFamily {
    type Err = DigitalOceanError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "droplets" => Ok(Self::Droplets),
            "vpcs" => Ok(Self::Vpcs),
            "firewalls" => Ok(Self::Firewalls),
            _ => Err(DigitalOceanError::InvalidFamily),
        }
    }
}
