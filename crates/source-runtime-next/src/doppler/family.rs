#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum DopplerFamily {
    Secrets,
    Projects,
    AuditEvents,
}

impl DopplerFamily {
    #[cfg(test)]
    pub(super) const ALL: [Self; 3] = [Self::Secrets, Self::Projects, Self::AuditEvents];

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Secrets => "secrets",
            Self::Projects => "projects",
            Self::AuditEvents => "audit_events",
        }
    }

    pub(super) const fn path(self) -> &'static str {
        match self {
            Self::Secrets => "/v3/workplace/secrets",
            Self::Projects => "/v3/workplace/projects",
            Self::AuditEvents => "/v3/workplace/logs",
        }
    }

    pub(super) const fn event_kind(self) -> &'static str {
        match self {
            Self::Secrets => "doppler.secrets",
            Self::Projects => "doppler.projects",
            Self::AuditEvents => "doppler.audit_events",
        }
    }

    pub(super) const fn schema_ref(self) -> &'static str {
        match self {
            Self::Secrets => "doppler/secrets/v1",
            Self::Projects => "doppler/projects/v1",
            Self::AuditEvents => "doppler/audit_events/v1",
        }
    }

    pub(super) const fn record_class(self) -> &'static str {
        match self {
            Self::Secrets => "secret",
            Self::Projects => "asset",
            Self::AuditEvents => "audit_event",
        }
    }

    pub(super) const fn urn_kind(self) -> &'static str {
        match self {
            Self::Secrets => "doppler_secrets",
            Self::Projects => "doppler_projects",
            Self::AuditEvents => "doppler_audit_events",
        }
    }

    pub(super) const fn required_attributes(self) -> &'static [&'static str] {
        match self {
            Self::Secrets => &["tenant_id", "source_event_id", "secret_id", "secret_name"],
            Self::Projects => &[
                "tenant_id",
                "source_event_id",
                "resource_urn",
                "resource_type",
                "resource_id",
            ],
            Self::AuditEvents => &["tenant_id", "source_event_id", "event_type", "actor_id"],
        }
    }
}
