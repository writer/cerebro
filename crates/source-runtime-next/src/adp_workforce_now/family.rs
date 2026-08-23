use std::str::FromStr;

use super::AdpError;

/// Closed ADP Workforce Now catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AdpFamily {
    /// Workforce change event notifications.
    EventNotifications,
    /// Workforce worker profiles.
    Users,
}

impl AdpFamily {
    /// Every provider-declared family.
    pub const ALL: [Self; 2] = [Self::EventNotifications, Self::Users];

    /// Exact catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventNotifications => "event_notifications",
            Self::Users => "users",
        }
    }

    /// Exact provider path.
    pub const fn path(self) -> &'static str {
        match self {
            Self::EventNotifications => "/core/v1/event-notification-messages",
            Self::Users => "/hr/v2/workers",
        }
    }

    /// Exact provider response array key.
    pub const fn response_key(self) -> &'static str {
        match self {
            Self::EventNotifications => "events",
            Self::Users => "workers",
        }
    }

    /// Stable provider identity field.
    pub const fn id_field(self) -> &'static str {
        match self {
            Self::EventNotifications => "eventID",
            Self::Users => "associateOID",
        }
    }

    /// Exact event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::EventNotifications => "adp_workforce_now.event_notifications",
            Self::Users => "adp_workforce_now.users",
        }
    }

    /// Exact schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::EventNotifications => "adp_workforce_now/event_notifications/v1",
            Self::Users => "adp_workforce_now/users/v1",
        }
    }

    pub(super) const fn required_attributes(self) -> &'static [&'static str] {
        match self {
            Self::EventNotifications => &["tenant_id", "source_event_id", "event_type"],
            Self::Users => &["tenant_id", "source_event_id", "user_id"],
        }
    }

    pub(super) const fn required_payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::EventNotifications => &["eventID", "eventNameCode"],
            Self::Users => &["associateOID"],
        }
    }
}

impl FromStr for AdpFamily {
    type Err = AdpError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AdpError::InvalidFamily)
    }
}
