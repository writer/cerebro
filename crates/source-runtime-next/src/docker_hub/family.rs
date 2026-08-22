use std::str::FromStr;

use super::DockerHubError;

/// Closed Docker Hub family vocabulary for the provider-verified Rust slice.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DockerHubFamily {
    /// One repository in a configured namespace.
    Repositories,
}

impl DockerHubFamily {
    /// Every provider-verified Docker Hub family.
    pub const ALL: [Self; 1] = [Self::Repositories];

    /// Exact catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Repositories => "repositories",
        }
    }

    /// Exact admitted event kind.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Repositories => "docker_hub.repositories",
        }
    }

    /// Exact admitted event schema.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Repositories => "docker_hub/repositories/v1",
        }
    }
}

impl FromStr for DockerHubFamily {
    type Err = DockerHubError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(DockerHubError::InvalidFamily)
    }
}
