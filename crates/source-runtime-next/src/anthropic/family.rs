//! Closed Anthropic family and provider contract definitions.

use std::str::FromStr;

use super::AnthropicError;

/// Anthropic authentication capability required by one family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnthropicAuthentication {
    /// Admin API key in `x-api-key` or an OAuth bearer with `org:admin`.
    AdminKeyOrOrgAdminBearer,
    /// OAuth bearer with `org:admin`; Admin API keys are not accepted.
    OrgAdminBearer,
    /// Compliance Access Key in `x-api-key`.
    ComplianceAccessKey,
}

/// Provider pagination contract for one family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PaginationKind {
    None,
    AfterId,
    Page,
}

/// One scalar field selected from a provider record.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AttributeBinding {
    pub(crate) name: &'static str,
    pub(crate) paths: &'static [&'static str],
}

/// Closed Anthropic Admin and Compliance API family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AnthropicFamily {
    /// Enterprise analytics cost buckets.
    AnalyticsCost,
    /// Organization API keys.
    ApiKey,
    /// Compliance audit activity.
    ComplianceActivity,
    /// Compliance directory groups.
    ComplianceGroup,
    /// Compliance directory group members.
    ComplianceGroupMember,
    /// Compliance directory organizations.
    ComplianceOrganization,
    /// Effective organization settings.
    ComplianceOrganizationSetting,
    /// Compliance directory organization users.
    ComplianceOrganizationUser,
    /// Claude projects exposed by the Compliance API.
    ComplianceProject,
    /// Claude project collaborators.
    ComplianceProjectCollaborator,
    /// Compliance directory roles.
    ComplianceRole,
    /// Compliance directory role permissions.
    ComplianceRolePermission,
    /// Admin usage cost report buckets.
    CostReport,
    /// External key configurations.
    ExternalKey,
    /// Workload identity federation issuers.
    FederationIssuer,
    /// Workload identity federation rules.
    FederationRule,
    /// Pending organization invites.
    Invite,
    /// Current organization profile.
    Organization,
    /// Organization rate limits.
    RateLimit,
    /// Workload service accounts.
    ServiceAccount,
    /// Effective spend limits.
    SpendLimit,
    /// Spend-limit increase requests.
    SpendLimitIncreaseRequest,
    /// Claude Code usage report buckets.
    UsageReportClaudeCode,
    /// Messages usage report buckets.
    UsageReportMessage,
    /// Organization users and roles.
    User,
    /// Organization workspaces.
    Workspace,
    /// Workspace members and roles.
    WorkspaceMember,
    /// Workspace rate limits.
    WorkspaceRateLimit,
}

impl AnthropicFamily {
    /// Every family retained by the Go Anthropic oracle.
    pub const ALL: [Self; 28] = [
        Self::AnalyticsCost,
        Self::ApiKey,
        Self::ComplianceActivity,
        Self::ComplianceGroup,
        Self::ComplianceGroupMember,
        Self::ComplianceOrganization,
        Self::ComplianceOrganizationSetting,
        Self::ComplianceOrganizationUser,
        Self::ComplianceProject,
        Self::ComplianceProjectCollaborator,
        Self::ComplianceRole,
        Self::ComplianceRolePermission,
        Self::CostReport,
        Self::ExternalKey,
        Self::FederationIssuer,
        Self::FederationRule,
        Self::Invite,
        Self::Organization,
        Self::RateLimit,
        Self::ServiceAccount,
        Self::SpendLimit,
        Self::SpendLimitIncreaseRequest,
        Self::UsageReportClaudeCode,
        Self::UsageReportMessage,
        Self::User,
        Self::Workspace,
        Self::WorkspaceMember,
        Self::WorkspaceRateLimit,
    ];

    /// Return the exact Go source runtime family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnalyticsCost => "analytics_cost",
            Self::ApiKey => "api_key",
            Self::ComplianceActivity => "compliance_activity",
            Self::ComplianceGroup => "compliance_group",
            Self::ComplianceGroupMember => "compliance_group_member",
            Self::ComplianceOrganization => "compliance_organization",
            Self::ComplianceOrganizationSetting => "compliance_organization_setting",
            Self::ComplianceOrganizationUser => "compliance_organization_user",
            Self::ComplianceProject => "compliance_project",
            Self::ComplianceProjectCollaborator => "compliance_project_collaborator",
            Self::ComplianceRole => "compliance_role",
            Self::ComplianceRolePermission => "compliance_role_permission",
            Self::CostReport => "cost_report",
            Self::ExternalKey => "external_key",
            Self::FederationIssuer => "federation_issuer",
            Self::FederationRule => "federation_rule",
            Self::Invite => "invite",
            Self::Organization => "organization",
            Self::RateLimit => "rate_limit",
            Self::ServiceAccount => "service_account",
            Self::SpendLimit => "spend_limit",
            Self::SpendLimitIncreaseRequest => "spend_limit_increase_request",
            Self::UsageReportClaudeCode => "usage_report_claude_code",
            Self::UsageReportMessage => "usage_report_message",
            Self::User => "user",
            Self::Workspace => "workspace",
            Self::WorkspaceMember => "workspace_member",
            Self::WorkspaceRateLimit => "workspace_rate_limit",
        }
    }

    /// Return the exact emitted event kind.
    pub fn provider_kind(self) -> String {
        format!("anthropic.{}", self.as_str())
    }

    /// Return the exact public event schema reference.
    pub fn schema_ref(self) -> String {
        format!("anthropic/{}/v1", self.as_str())
    }

    /// Return the exact provider path template.
    pub const fn path(self) -> &'static str {
        match self {
            Self::AnalyticsCost => "/organizations/analytics/cost_report",
            Self::ApiKey => "/organizations/api_keys",
            Self::ComplianceActivity => "/compliance/activities",
            Self::ComplianceGroup => "/compliance/groups",
            Self::ComplianceGroupMember => "/compliance/groups/{group_id}/members",
            Self::ComplianceOrganization => "/compliance/organizations",
            Self::ComplianceOrganizationSetting => {
                "/compliance/organizations/{organization_uuid}/settings"
            }
            Self::ComplianceOrganizationUser => {
                "/compliance/organizations/{organization_uuid}/users"
            }
            Self::ComplianceProject => "/compliance/apps/projects",
            Self::ComplianceProjectCollaborator => {
                "/compliance/apps/projects/{project_id}/collaborators"
            }
            Self::ComplianceRole => "/compliance/organizations/{organization_uuid}/roles",
            Self::ComplianceRolePermission => {
                "/compliance/organizations/{organization_uuid}/roles/{role_id}/permissions"
            }
            Self::CostReport => "/organizations/cost_report",
            Self::ExternalKey => "/organizations/external_keys",
            Self::FederationIssuer => "/organizations/federation_issuers",
            Self::FederationRule => "/organizations/federation_rules",
            Self::Invite => "/organizations/invites",
            Self::Organization => "/organizations/me",
            Self::RateLimit => "/organizations/rate_limits",
            Self::ServiceAccount => "/organizations/service_accounts",
            Self::SpendLimit => "/organizations/spend_limits/effective",
            Self::SpendLimitIncreaseRequest => "/organizations/spend_limit_increase_requests",
            Self::UsageReportClaudeCode => "/organizations/usage_report/claude_code",
            Self::UsageReportMessage => "/organizations/usage_report/messages",
            Self::User => "/organizations/users",
            Self::Workspace => "/organizations/workspaces",
            Self::WorkspaceMember => "/organizations/workspaces/{workspace_id}/members",
            Self::WorkspaceRateLimit => "/organizations/workspaces/{workspace_id}/rate_limits",
        }
    }

    /// Return the provider authorization capability without credential material.
    pub const fn authentication(self) -> AnthropicAuthentication {
        match self {
            Self::ServiceAccount | Self::FederationIssuer | Self::FederationRule => {
                AnthropicAuthentication::OrgAdminBearer
            }
            Self::ComplianceActivity
            | Self::ComplianceGroup
            | Self::ComplianceGroupMember
            | Self::ComplianceOrganization
            | Self::ComplianceOrganizationSetting
            | Self::ComplianceOrganizationUser
            | Self::ComplianceProject
            | Self::ComplianceProjectCollaborator
            | Self::ComplianceRole
            | Self::ComplianceRolePermission => AnthropicAuthentication::ComplianceAccessKey,
            _ => AnthropicAuthentication::AdminKeyOrOrgAdminBearer,
        }
    }

    pub(crate) const fn pagination(self) -> PaginationKind {
        match self {
            Self::Organization
            | Self::ComplianceOrganization
            | Self::ComplianceOrganizationSetting => PaginationKind::None,
            Self::ExternalKey
            | Self::AnalyticsCost
            | Self::CostReport
            | Self::UsageReportClaudeCode
            | Self::UsageReportMessage
            | Self::RateLimit
            | Self::WorkspaceRateLimit
            | Self::SpendLimit
            | Self::SpendLimitIncreaseRequest
            | Self::ComplianceOrganizationUser
            | Self::ComplianceProject
            | Self::ComplianceProjectCollaborator
            | Self::ComplianceRole
            | Self::ComplianceRolePermission
            | Self::ComplianceGroup
            | Self::ComplianceGroupMember => PaginationKind::Page,
            _ => PaginationKind::AfterId,
        }
    }

    pub(crate) const fn singleton(self) -> bool {
        matches!(self, Self::Organization)
    }

    pub(crate) const fn path_parameters(self) -> &'static [&'static str] {
        match self {
            Self::ComplianceGroupMember => &["group_id"],
            Self::ComplianceOrganizationSetting
            | Self::ComplianceOrganizationUser
            | Self::ComplianceRole => &["organization_uuid"],
            Self::ComplianceRolePermission => &["organization_uuid", "role_id"],
            Self::ComplianceProjectCollaborator => &["project_id"],
            Self::WorkspaceMember | Self::WorkspaceRateLimit => &["workspace_id"],
            _ => &[],
        }
    }

    pub(crate) const fn query_parameters(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::ApiKey => &[("status", "status"), ("workspace_id", "workspace_id")],
            Self::Workspace => &[("include_archived", "include_archived")],
            Self::RateLimit => &[("model", "model")],
            Self::SpendLimit => &[
                ("actor_ids[]", "actor_ids"),
                ("period[]", "periods"),
                ("user_ids[]", "user_ids"),
            ],
            Self::SpendLimitIncreaseRequest => {
                &[("actor_ids[]", "actor_ids"), ("status[]", "status")]
            }
            Self::ComplianceActivity => &[
                ("activity_types[]", "activity_types"),
                ("actor_ids[]", "actor_ids"),
                ("created_at.gt", "created_at_gt"),
                ("created_at.gte", "created_at_gte"),
                ("created_at.lt", "created_at_lt"),
                ("created_at.lte", "created_at_lte"),
                ("organization_ids[]", "organization_ids"),
            ],
            Self::AnalyticsCost
            | Self::CostReport
            | Self::UsageReportClaudeCode
            | Self::UsageReportMessage => &[
                ("api_key_ids[]", "api_key_ids"),
                ("bucket_width", "bucket_width"),
                ("context_window[]", "context_windows"),
                ("ending_at", "ending_at"),
                ("group_by[]", "group_by"),
                ("inference_geos[]", "inference_geos"),
                ("models[]", "models"),
                ("service_tiers[]", "service_tiers"),
                ("speeds[]", "speeds"),
                ("starting_at", "starting_at"),
                ("terminal_types[]", "terminal_types"),
                ("workspace_ids[]", "workspace_ids"),
            ],
            _ => &[],
        }
    }

    pub(crate) const fn list_keys(self) -> &'static [&'static str] {
        match self {
            Self::ComplianceOrganizationSetting => &["settings"],
            _ => &[],
        }
    }

    pub(crate) const fn id_paths(self) -> &'static [&'static str] {
        match self {
            Self::ComplianceOrganization => &["uuid", "id"],
            Self::ComplianceOrganizationSetting => &["name"],
            Self::ComplianceOrganizationUser => &["id", "user_id"],
            Self::ComplianceRole => &["id", "role_id"],
            Self::ComplianceRolePermission => &["id", "permission_id", "permission", "name"],
            Self::ComplianceGroup => &["id", "group_id"],
            Self::ComplianceGroupMember => &["user_id", "id", "email"],
            Self::ComplianceProject => &["id", "project_id"],
            Self::ComplianceProjectCollaborator => &[
                "id",
                "assignment_id",
                "principal.id",
                "user.id",
                "group.id",
                "organization.id",
            ],
            Self::RateLimit | Self::WorkspaceRateLimit => &["id", "group_type", "model", "name"],
            Self::SpendLimit => &["spend_limit_id", "id", "scope.user_id", "actor.user_id"],
            _ => &["id"],
        }
    }

    pub(crate) const fn timestamp_paths(self) -> &'static [&'static str] {
        match self {
            Self::User | Self::WorkspaceMember => &["added_at"],
            Self::Invite => &["created_at", "expires_at"],
            Self::Workspace => &["created_at", "archived_at"],
            Self::ApiKey | Self::ExternalKey => &["created_at", "last_used_at"],
            Self::ServiceAccount
            | Self::ComplianceActivity
            | Self::ComplianceOrganization
            | Self::ComplianceOrganizationUser => &["created_at"],
            Self::FederationIssuer
            | Self::FederationRule
            | Self::ComplianceRole
            | Self::ComplianceRolePermission
            | Self::ComplianceGroup
            | Self::ComplianceGroupMember
            | Self::ComplianceProjectCollaborator
            | Self::SpendLimit
            | Self::SpendLimitIncreaseRequest => &["created_at", "updated_at"],
            Self::ComplianceProject => &["created_at", "updated_at", "archived_at"],
            Self::AnalyticsCost
            | Self::CostReport
            | Self::UsageReportClaudeCode
            | Self::UsageReportMessage => &["start_time", "starting_at", "date"],
            Self::RateLimit | Self::WorkspaceRateLimit => &["updated_at"],
            Self::Organization | Self::ComplianceOrganizationSetting => &[],
        }
    }

    pub(crate) const fn required_attributes(self) -> &'static [&'static str] {
        match self {
            Self::Organization => &["organization_id"],
            Self::User => &["user_id"],
            Self::Invite => &["invite_id"],
            Self::Workspace => &["workspace_id"],
            Self::WorkspaceMember => &["user_id", "workspace_id"],
            Self::ApiKey => &["api_key_id"],
            Self::ExternalKey => &["external_key_id"],
            Self::ServiceAccount => &["service_account_id"],
            Self::FederationIssuer => &["federation_issuer_id"],
            Self::FederationRule => &["federation_rule_id"],
            Self::AnalyticsCost
            | Self::CostReport
            | Self::UsageReportClaudeCode
            | Self::UsageReportMessage
            | Self::RateLimit
            | Self::SpendLimit => &["external_id"],
            Self::WorkspaceRateLimit => &["external_id", "workspace_id"],
            Self::SpendLimitIncreaseRequest => &["request_id"],
            Self::ComplianceActivity => &["activity_id"],
            Self::ComplianceOrganization => &["organization_uuid"],
            Self::ComplianceOrganizationUser => &["organization_uuid", "user_id"],
            Self::ComplianceRole => &["organization_uuid", "role_id"],
            Self::ComplianceRolePermission => &["organization_uuid", "role_id", "permission_id"],
            Self::ComplianceGroup => &["group_id"],
            Self::ComplianceGroupMember => &["group_id", "user_id"],
            Self::ComplianceProject => &["project_id"],
            Self::ComplianceProjectCollaborator => {
                &["project_id", "principal_type", "principal_id", "role_id"]
            }
            Self::ComplianceOrganizationSetting => &["organization_uuid", "setting_name"],
        }
    }

    pub(crate) const fn required_payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::AnalyticsCost
            | Self::CostReport
            | Self::UsageReportClaudeCode
            | Self::UsageReportMessage
            | Self::RateLimit
            | Self::WorkspaceRateLimit
            | Self::SpendLimit
            | Self::ComplianceProjectCollaborator => &[],
            Self::ComplianceOrganization => &["uuid"],
            Self::ComplianceOrganizationSetting => &["name"],
            _ => &["id"],
        }
    }
}

impl FromStr for AnthropicFamily {
    type Err = AnthropicError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(AnthropicError::InvalidFamily)
    }
}
