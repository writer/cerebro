use super::{GitHubError, GitHubFamily};

/// One closed event contract compiled from `sources/github/catalog.yaml`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitHubEventContract {
    /// Exact event kind admitted by the source catalog.
    pub kind: &'static str,
    /// Exact schema reference admitted by the source catalog.
    pub schema_ref: &'static str,
    /// Required normalized attributes.
    pub required_attributes: &'static [&'static str],
    /// Required normalized payload fields.
    pub required_payload_fields: &'static [&'static str],
}

/// Closed GitHub runtime definition compiled from the six catalog families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitHubRuntimeDefinition {
    /// Source identifier.
    pub source_id: &'static str,
    /// Selected source family.
    pub family: GitHubFamily,
    /// Exact events this family may emit.
    pub event_contracts: &'static [GitHubEventContract],
    /// Whether this is a bounded pull family.
    pub pull: bool,
}

const AUDIT: GitHubEventContract = contract(
    "github.audit",
    "github/audit/v1",
    &["action", "org"],
    &["action", "org"],
);
const REPOSITORY: GitHubEventContract = contract(
    "github.code.repository",
    "github/code_repository/v1",
    &["owner_login", "repository", "resource_id", "resource_type"],
    &["full_name", "owner_login"],
);
const DEPENDABOT: GitHubEventContract = contract(
    "github.dependabot_alert",
    "github/dependabot_alert/v1",
    &["owner", "repo", "repository", "state"],
    &["number", "repository", "state"],
);
const PULL_REQUEST: GitHubEventContract = contract(
    "github.pull_request",
    "github/pull_request/v1",
    &["owner", "repo", "repository"],
    &["number", "repository"],
);
const ORG_MEMBER: GitHubEventContract = contract(
    "github.org_member",
    "github/org_member/v1",
    &["login", "owner", "role"],
    &["login", "org", "role"],
);
const ORG_INSTALLATION: GitHubEventContract = contract(
    "github.org_installation",
    "github/org_installation/v1",
    &["app_slug", "installation_id", "owner"],
    &["app_slug", "id", "org"],
);
const SECRET_SCANNING: GitHubEventContract = contract(
    "github.secret_scanning_alert",
    "github/secret_scanning_alert/v1",
    &["owner", "state"],
    &["number", "state"],
);

const fn contract(
    kind: &'static str,
    schema_ref: &'static str,
    required_attributes: &'static [&'static str],
    required_payload_fields: &'static [&'static str],
) -> GitHubEventContract {
    GitHubEventContract {
        kind,
        schema_ref,
        required_attributes,
        required_payload_fields,
    }
}

impl GitHubRuntimeDefinition {
    /// Compile one catalog family into its closed runtime definition.
    pub fn compile(family: GitHubFamily) -> Result<Self, GitHubError> {
        let event_contracts: &'static [GitHubEventContract] = match family {
            GitHubFamily::Audit => &[AUDIT],
            GitHubFamily::Repository => &[REPOSITORY],
            GitHubFamily::DependabotAlert => &[DEPENDABOT],
            GitHubFamily::OrganizationInventory => &[ORG_MEMBER, ORG_INSTALLATION],
            GitHubFamily::PullRequest => &[PULL_REQUEST],
            GitHubFamily::SecretScanningAlert => &[SECRET_SCANNING],
        };
        Ok(Self {
            source_id: "github",
            family,
            event_contracts,
            pull: true,
        })
    }

    pub(super) fn contract_for_kind(self, kind: &str) -> Option<GitHubEventContract> {
        self.event_contracts
            .iter()
            .copied()
            .find(|contract| contract.kind == kind)
    }
}
