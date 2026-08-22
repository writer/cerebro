//! Closed Okta source-family catalog.

use std::str::FromStr;

use super::OktaError;

/// Okta families preserved by the Go compatibility runtime.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OktaFamily {
    /// System Log audit events.
    Audit,
    /// User inventory.
    User,
    /// Group inventory.
    Group,
    /// Group membership inventory.
    GroupMembership,
    /// Application inventory.
    Application,
    /// User and group application assignments.
    AppAssignment,
    /// User administrator roles.
    AdminRole,
    /// Policy rules.
    PolicyRule,
    /// API token metadata.
    ApiToken,
    /// Authorization servers.
    AuthorizationServer,
    /// Authenticators.
    Authenticator,
    /// Brands.
    Brand,
    /// Device assurance policies.
    DeviceAssurance,
    /// Event hooks.
    EventHook,
    /// Identity providers.
    IdentityProvider,
    /// Inline hooks.
    InlineHook,
    /// Log streams.
    LogStream,
    /// Network zones.
    NetworkZone,
    /// ThreatInsight configuration.
    ThreatInsight,
    /// Trusted origins.
    TrustedOrigin,
}

impl OktaFamily {
    /// Every family in the public Okta runtime catalog.
    pub const ALL: [Self; 20] = [
        Self::Audit,
        Self::AdminRole,
        Self::AppAssignment,
        Self::Application,
        Self::ApiToken,
        Self::AuthorizationServer,
        Self::Authenticator,
        Self::Brand,
        Self::DeviceAssurance,
        Self::EventHook,
        Self::Group,
        Self::GroupMembership,
        Self::IdentityProvider,
        Self::InlineHook,
        Self::LogStream,
        Self::NetworkZone,
        Self::PolicyRule,
        Self::ThreatInsight,
        Self::TrustedOrigin,
        Self::User,
    ];

    /// Return the exact runtime family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::User => "user",
            Self::Group => "group",
            Self::GroupMembership => "group_membership",
            Self::Application => "application",
            Self::AppAssignment => "app_assignment",
            Self::AdminRole => "admin_role",
            Self::PolicyRule => "policy_rule",
            Self::ApiToken => "api_token",
            Self::AuthorizationServer => "authorization_server",
            Self::Authenticator => "authenticator",
            Self::Brand => "brand",
            Self::DeviceAssurance => "device_assurance",
            Self::EventHook => "event_hook",
            Self::IdentityProvider => "identity_provider",
            Self::InlineHook => "inline_hook",
            Self::LogStream => "log_stream",
            Self::NetworkZone => "network_zone",
            Self::ThreatInsight => "threat_insight",
            Self::TrustedOrigin => "trusted_origin",
        }
    }

    /// Return the exact event kind emitted by Go.
    pub fn provider_kind(self) -> String {
        format!("okta.{}", self.as_str())
    }

    /// Return the exact event schema reference emitted by Go.
    pub fn schema_ref(self) -> String {
        format!("okta/{}/v1", self.as_str())
    }

    pub(super) const fn endpoint(self) -> &'static str {
        match self {
            Self::Audit => "/api/v1/logs",
            Self::User => "/api/v1/users",
            Self::Group => "/api/v1/groups",
            Self::Application => "/api/v1/apps",
            Self::ApiToken => "/api/v1/api-tokens",
            Self::AuthorizationServer => "/api/v1/authorizationServers",
            Self::Authenticator => "/api/v1/authenticators",
            Self::Brand => "/api/v1/brands",
            Self::DeviceAssurance => "/api/v1/device-assurances",
            Self::EventHook => "/api/v1/eventHooks",
            Self::IdentityProvider => "/api/v1/idps",
            Self::InlineHook => "/api/v1/inlineHooks",
            Self::LogStream => "/api/v1/logStreams",
            Self::NetworkZone => "/api/v1/zones",
            Self::ThreatInsight => "/api/v1/threats/configuration",
            Self::TrustedOrigin => "/api/v1/trustedOrigins",
            Self::GroupMembership | Self::AppAssignment | Self::AdminRole | Self::PolicyRule => "",
        }
    }

    pub(super) const fn singleton(self) -> bool {
        matches!(self, Self::ThreatInsight)
    }
}

impl FromStr for OktaFamily {
    type Err = OktaError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(OktaError::InvalidFamily)
    }
}
