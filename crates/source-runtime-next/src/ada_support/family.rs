use std::str::FromStr;

use super::AdaSupportError;

/// Closed Ada Support catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AdaSupportFamily {
    /// Administrative audit events.
    AuditEvents,
    /// Exported support conversations.
    Conversations,
    /// Customer end users.
    EndUsers,
    /// Knowledge-base articles.
    KnowledgeArticles,
    /// Configured platform integrations.
    PlatformIntegrations,
}

impl AdaSupportFamily {
    /// Every provider-declared family in catalog order.
    pub const ALL: [Self; 5] = [
        Self::AuditEvents,
        Self::Conversations,
        Self::EndUsers,
        Self::KnowledgeArticles,
        Self::PlatformIntegrations,
    ];

    /// Exact catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditEvents => "audit_events",
            Self::Conversations => "conversations",
            Self::EndUsers => "end_users",
            Self::KnowledgeArticles => "knowledge_articles",
            Self::PlatformIntegrations => "platform_integrations",
        }
    }

    /// Exact provider path relative to the configured API base.
    pub const fn path(self) -> &'static str {
        match self {
            Self::AuditEvents => "/v2/analytics/audit-log/events/",
            Self::Conversations => "/v2/export/conversations",
            Self::EndUsers => "/v2/end-users/",
            Self::KnowledgeArticles => "/v2/knowledge/articles/",
            Self::PlatformIntegrations => "/v2/platform-integrations/",
        }
    }

    /// Exact provider response array key.
    pub const fn response_key(self) -> &'static str {
        match self {
            Self::Conversations => "items",
            _ => "data",
        }
    }

    /// Exact next-page field inside the meta envelope.
    pub const fn next_page_key(self) -> &'static str {
        match self {
            Self::Conversations => "next_page_uri",
            _ => "next_page_url",
        }
    }

    /// Stable provider identity field.
    pub const fn id_field(self) -> &'static str {
        match self {
            Self::Conversations => "_id",
            Self::EndUsers => "end_user_id",
            _ => "id",
        }
    }

    /// Exact record selector.
    pub const fn record_selector(self) -> &'static str {
        match self {
            Self::Conversations => "$.items[*]",
            _ => "$.data[*]",
        }
    }

    /// Exact event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::AuditEvents => "ada_support.audit_events",
            Self::Conversations => "ada_support.conversations",
            Self::EndUsers => "ada_support.end_users",
            Self::KnowledgeArticles => "ada_support.knowledge_articles",
            Self::PlatformIntegrations => "ada_support.platform_integrations",
        }
    }

    /// Exact schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::AuditEvents => "ada_support/audit_events/v1",
            Self::Conversations => "ada_support/conversations/v1",
            Self::EndUsers => "ada_support/end_users/v1",
            Self::KnowledgeArticles => "ada_support/knowledge_articles/v1",
            Self::PlatformIntegrations => "ada_support/platform_integrations/v1",
        }
    }

    pub(super) const fn required_attributes(self) -> &'static [&'static str] {
        match self {
            Self::AuditEvents => &["tenant_id", "source_event_id", "event_type", "actor_id"],
            Self::EndUsers => &["tenant_id", "source_event_id", "user_id"],
            Self::KnowledgeArticles => {
                &["tenant_id", "source_event_id", "policy_id", "policy_name"]
            }
            Self::Conversations | Self::PlatformIntegrations => &[
                "tenant_id",
                "source_event_id",
                "resource_urn",
                "resource_type",
                "resource_id",
            ],
        }
    }

    pub(super) const fn required_payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::Conversations => &["_id"],
            Self::EndUsers => &["end_user_id"],
            Self::AuditEvents | Self::KnowledgeArticles | Self::PlatformIntegrations => &["id"],
        }
    }
}

impl FromStr for AdaSupportFamily {
    type Err = AdaSupportError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AdaSupportError::InvalidFamily)
    }
}
