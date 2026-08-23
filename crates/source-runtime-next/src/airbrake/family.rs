use std::str::FromStr;

use super::AirbrakeError;

/// Closed Airbrake catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AirbrakeFamily {
    /// Project deploy records.
    Deploys,
    /// Cross-project error groups.
    Groups,
    /// Project activity records.
    ProjectActivities,
    /// Account projects.
    Projects,
    /// Uploaded project source maps.
    SourceMaps,
}

impl AirbrakeFamily {
    /// Every provider-declared family in catalog order.
    pub const ALL: [Self; 5] = [
        Self::Deploys,
        Self::Groups,
        Self::ProjectActivities,
        Self::Projects,
        Self::SourceMaps,
    ];

    /// Exact catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deploys => "deploys",
            Self::Groups => "groups",
            Self::ProjectActivities => "project_activities",
            Self::Projects => "projects",
            Self::SourceMaps => "source_maps",
        }
    }

    /// Provider path relative to the fixed API origin.
    pub fn path(self, project_id: Option<&str>) -> Result<String, AirbrakeError> {
        Ok(match self {
            Self::Deploys => format!(
                "/api/v4/projects/{}/deploys",
                project_id.ok_or(AirbrakeError::MissingProjectId)?
            ),
            Self::Groups => "/api/v4/groups".to_owned(),
            Self::ProjectActivities => format!(
                "/api/v4/projects/{}/activities",
                project_id.ok_or(AirbrakeError::MissingProjectId)?
            ),
            Self::Projects => "/api/v4/projects".to_owned(),
            Self::SourceMaps => format!(
                "/api/v4/projects/{}/sourcemaps",
                project_id.ok_or(AirbrakeError::MissingProjectId)?
            ),
        })
    }

    /// JSON response collection field.
    pub const fn response_key(self) -> &'static str {
        match self {
            Self::Deploys => "deploys",
            Self::Groups => "groups",
            Self::ProjectActivities => "activities",
            Self::Projects => "projects",
            Self::SourceMaps => "sourcemaps",
        }
    }

    /// Whether this family supports the checked provider cursor.
    pub const fn cursor_paginated(self) -> bool {
        matches!(self, Self::Groups)
    }

    /// Whether this family requires configured project scope.
    pub const fn project_scoped(self) -> bool {
        matches!(
            self,
            Self::Deploys | Self::ProjectActivities | Self::SourceMaps
        )
    }

    /// Stable provider identity field.
    pub const fn id_field(self) -> &'static str {
        "id"
    }

    /// Exact event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Deploys => "airbrake.deploys",
            Self::Groups => "airbrake.groups",
            Self::ProjectActivities => "airbrake.project_activities",
            Self::Projects => "airbrake.projects",
            Self::SourceMaps => "airbrake.source_maps",
        }
    }

    /// Exact schema reference.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Deploys => "airbrake/deploys/v1",
            Self::Groups => "airbrake/groups/v1",
            Self::ProjectActivities => "airbrake/project_activities/v1",
            Self::Projects => "airbrake/projects/v1",
            Self::SourceMaps => "airbrake/source_maps/v1",
        }
    }

    pub(super) const fn required_attributes(self) -> &'static [&'static str] {
        match self {
            Self::Groups => &[
                "tenant_id",
                "source_event_id",
                "finding_id",
                "severity",
                "status",
            ],
            Self::ProjectActivities => &["tenant_id", "source_event_id", "event_type", "actor_id"],
            Self::Deploys | Self::Projects | Self::SourceMaps => &[
                "tenant_id",
                "source_event_id",
                "resource_urn",
                "resource_type",
                "resource_id",
            ],
        }
    }

    pub(super) const fn required_payload_fields(self) -> &'static [&'static str] {
        &["id"]
    }
}

impl FromStr for AirbrakeFamily {
    type Err = AirbrakeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AirbrakeError::InvalidFamily)
    }
}
