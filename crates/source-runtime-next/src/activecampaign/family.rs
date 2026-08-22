use std::str::FromStr;

use super::ActiveCampaignError;

/// Closed ActiveCampaign catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ActiveCampaignFamily {
    /// CRM accounts.
    Accounts,
    /// Marketing automations.
    Automations,
    /// Marketing campaigns.
    Campaigns,
    /// CRM contacts.
    Contacts,
    /// Account users.
    Users,
}

impl ActiveCampaignFamily {
    /// Every provider-declared family in catalog order.
    pub const ALL: [Self; 5] = [
        Self::Accounts,
        Self::Automations,
        Self::Campaigns,
        Self::Contacts,
        Self::Users,
    ];

    /// Exact catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accounts => "accounts",
            Self::Automations => "automations",
            Self::Campaigns => "campaigns",
            Self::Contacts => "contacts",
            Self::Users => "users",
        }
    }

    /// Exact provider path.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Accounts => "/api/3/accounts",
            Self::Automations => "/api/3/automations",
            Self::Campaigns => "/api/3/campaigns",
            Self::Contacts => "/api/3/contacts",
            Self::Users => "/api/3/users",
        }
    }

    /// Exact response array key.
    pub const fn response_key(self) -> &'static str {
        self.as_str()
    }

    /// Exact event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Accounts => "activecampaign.accounts",
            Self::Automations => "activecampaign.automations",
            Self::Campaigns => "activecampaign.campaigns",
            Self::Contacts => "activecampaign.contacts",
            Self::Users => "activecampaign.users",
        }
    }

    /// Exact schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Accounts => "activecampaign/accounts/v1",
            Self::Automations => "activecampaign/automations/v1",
            Self::Campaigns => "activecampaign/campaigns/v1",
            Self::Contacts => "activecampaign/contacts/v1",
            Self::Users => "activecampaign/users/v1",
        }
    }
}

impl FromStr for ActiveCampaignFamily {
    type Err = ActiveCampaignError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(ActiveCampaignError::InvalidFamily)
    }
}
