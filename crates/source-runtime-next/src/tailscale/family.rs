use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use super::TailscaleError;

/// Closed set of provider-specific families owned by the Tailscale source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailscaleFamily {
    /// Tailnet settings singleton.
    Tailnet,
    /// Tailnet users.
    User,
    /// Tailnet devices.
    Device,
    /// ACL groups.
    Group,
    /// ACL tag owners.
    Tag,
    /// Tailnet VIP services.
    Service,
    /// ACL grants.
    Grant,
}

impl TailscaleFamily {
    /// Exact family set in `sources/tailscale/catalog.yaml`.
    pub const ALL: [Self; 7] = [
        Self::Device,
        Self::Grant,
        Self::Group,
        Self::Service,
        Self::Tag,
        Self::Tailnet,
        Self::User,
    ];

    /// Catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tailnet => "tailnet",
            Self::User => "user",
            Self::Device => "device",
            Self::Group => "group",
            Self::Tag => "tag",
            Self::Service => "service",
            Self::Grant => "grant",
        }
    }

    /// Exact emitted event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Tailnet => "tailscale.tailnet",
            Self::User => "tailscale.user",
            Self::Device => "tailscale.device",
            Self::Group => "tailscale.group",
            Self::Tag => "tailscale.tag",
            Self::Service => "tailscale.service",
            Self::Grant => "tailscale.grant",
        }
    }

    /// Exact emitted schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Tailnet => "tailscale/tailnet/v1",
            Self::User => "tailscale/user/v1",
            Self::Device => "tailscale/device/v1",
            Self::Group => "tailscale/group/v1",
            Self::Tag => "tailscale/tag/v1",
            Self::Service => "tailscale/service/v1",
            Self::Grant => "tailscale/grant/v1",
        }
    }

    /// Go-oracle request path using Tailscale's authenticated-tailnet alias.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Tailnet => "/tailnet/-/settings",
            Self::User => "/tailnet/-/users",
            Self::Device => "/tailnet/-/devices",
            Self::Group | Self::Tag | Self::Grant => "/tailnet/-/acl",
            Self::Service => "/tailnet/-/vip-services",
        }
    }

    pub(super) const fn urn_kind(self) -> &'static str {
        match self {
            Self::Tailnet => "tailscale_tailnet",
            Self::User => "tailscale_user",
            Self::Device => "tailscale_device",
            Self::Group => "tailscale_group",
            Self::Tag => "tailscale_tag",
            Self::Service => "tailscale_service",
            Self::Grant => "tailscale_grant",
        }
    }

    pub(super) const fn required_attribute(self) -> &'static str {
        match self {
            Self::Tailnet => "tailnet",
            Self::User => "user_id",
            Self::Device => "device_id",
            Self::Group => "group_id",
            Self::Tag => "tag_id",
            Self::Service => "service_id",
            Self::Grant => "grant_id",
        }
    }

    pub(super) const fn required_attributes(self) -> &'static [&'static str] {
        match self {
            Self::Tailnet => &["tailnet"],
            Self::User => &["user_id", "login_name"],
            Self::Device => &["device_id"],
            Self::Group => &["group_id"],
            Self::Tag => &["tag_id"],
            Self::Service => &["service_id"],
            Self::Grant => &["grant_id"],
        }
    }

    pub(super) const fn required_payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::Service => &["name"],
            _ => &["id"],
        }
    }
}

impl fmt::Display for TailscaleFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for TailscaleFamily {
    type Err = TailscaleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(TailscaleError::UnknownFamily)
    }
}
