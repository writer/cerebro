use super::{DockerHubError, DockerHubFamily};

/// Exact event contract compiled for Docker Hub repositories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DockerHubEventContract {
    /// Exact provider event kind.
    pub kind: &'static str,
    /// Exact schema reference.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required provider payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed runtime definition for one provider-verified Docker Hub family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DockerHubRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected family.
    pub family: DockerHubFamily,
    /// Exact event contract.
    pub event_contract: DockerHubEventContract,
    /// Docker Hub repositories are bounded pull operations.
    pub pull: bool,
}

impl DockerHubRuntimeDefinition {
    /// Compile the closed provider-verified family.
    pub fn compile(family: DockerHubFamily) -> Result<Self, DockerHubError> {
        let event_contract = match family {
            DockerHubFamily::Repositories => DockerHubEventContract {
                kind: "docker_hub.repositories",
                schema_ref: "docker_hub/repositories/v1",
                required_attributes: &[
                    "tenant_id",
                    "source_event_id",
                    "resource_urn",
                    "resource_type",
                    "resource_id",
                ],
                required_payload_fields: &["name"],
            },
        };
        Ok(Self {
            source_id: "docker_hub",
            family,
            event_contract,
            pull: true,
        })
    }
}
