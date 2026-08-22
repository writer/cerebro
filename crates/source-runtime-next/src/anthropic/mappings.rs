//! Anthropic provider-field to canonical event-attribute mappings.

use super::family::{AnthropicFamily, AttributeBinding};

macro_rules! binding {
    ($name:literal => $($path:literal)|+ $(,)?) => {
        AttributeBinding { name: $name, paths: &[$($path),+] }
    };
}

impl AnthropicFamily {
    pub(crate) const fn attributes(self) -> &'static [AttributeBinding] {
        match self {
            Self::Organization => &[
                binding!("organization_id" => "id"),
                binding!("name" => "name"),
                binding!("type" => "type"),
            ],
            Self::User => &[
                binding!("user_id" => "id"),
                binding!("name" => "name"),
                binding!("email" => "email"),
                binding!("role" => "role"),
                binding!("status" => "status"),
                binding!("added_at" => "added_at"),
            ],
            Self::Invite => &[
                binding!("invite_id" => "id"),
                binding!("email" => "email"),
                binding!("role" => "role"),
                binding!("status" => "status"),
                binding!("created_at" => "created_at"),
                binding!("expires_at" => "expires_at"),
            ],
            Self::Workspace => &[
                binding!("workspace_id" => "id"),
                binding!("name" => "name"),
                binding!("display_color" => "display_color"),
                binding!("created_at" => "created_at"),
                binding!("archived_at" => "archived_at"),
            ],
            Self::WorkspaceMember => &[
                binding!("workspace_id" => "workspace_id"),
                binding!("user_id" => "id"|"user_id"),
                binding!("email" => "email"),
                binding!("name" => "name"),
                binding!("workspace_role" => "workspace_role"|"role"),
                binding!("added_at" => "added_at"),
            ],
            Self::ApiKey => &[
                binding!("api_key_id" => "id"),
                binding!("name" => "name"),
                binding!("status" => "status"),
                binding!("workspace_id" => "workspace_id"|"workspace.id"),
                binding!("owner_user_id" => "created_by.id"|"owner.id"|"user_id"),
                binding!("created_at" => "created_at"),
                binding!("last_used_at" => "last_used_at"),
            ],
            Self::ExternalKey => &[
                binding!("external_key_id" => "id"),
                binding!("name" => "name"),
                binding!("status" => "status"),
                binding!("provider" => "provider"),
                binding!("workspace_id" => "workspace_id"|"workspace.id"),
                binding!("created_at" => "created_at"),
                binding!("last_used_at" => "last_used_at"),
            ],
            Self::ServiceAccount => &[
                binding!("service_account_id" => "id"),
                binding!("name" => "name"),
                binding!("status" => "status"),
                binding!("description" => "description"),
                binding!("created_at" => "created_at"),
            ],
            Self::FederationIssuer => &[
                binding!("federation_issuer_id" => "id"),
                binding!("issuer" => "issuer"),
                binding!("name" => "name"),
                binding!("status" => "status"),
                binding!("created_at" => "created_at"),
                binding!("updated_at" => "updated_at"),
            ],
            Self::FederationRule => &[
                binding!("federation_rule_id" => "id"),
                binding!("issuer_id" => "issuer_id"|"federation_issuer_id"),
                binding!("service_account_id" => "service_account_id"),
                binding!("subject" => "subject"),
                binding!("scopes" => "scopes"),
                binding!("created_at" => "created_at"),
                binding!("updated_at" => "updated_at"),
            ],
            Self::AnalyticsCost
            | Self::CostReport
            | Self::UsageReportClaudeCode
            | Self::UsageReportMessage => REPORT,
            Self::RateLimit | Self::WorkspaceRateLimit => RATE_LIMIT,
            Self::SpendLimit => SPEND_LIMIT,
            Self::SpendLimitIncreaseRequest => SPEND_LIMIT_REQUEST,
            Self::ComplianceActivity => COMPLIANCE_ACTIVITY,
            Self::ComplianceOrganization => &[
                binding!("organization_uuid" => "uuid"),
                binding!("organization_id" => "id"|"organization_id"),
                binding!("name" => "name"),
                binding!("created_at" => "created_at"),
            ],
            Self::ComplianceOrganizationUser => &[
                binding!("organization_uuid" => "organization_uuid"),
                binding!("user_id" => "id"|"user_id"),
                binding!("name" => "full_name"|"name"),
                binding!("email" => "email"),
                binding!("role" => "organization_role"|"role"),
                binding!("organization_role" => "organization_role"|"role"),
                binding!("created_at" => "created_at"),
            ],
            Self::ComplianceRole => &[
                binding!("organization_uuid" => "organization_uuid"),
                binding!("role_id" => "id"|"role_id"),
                binding!("name" => "name"),
                binding!("description" => "description"),
                binding!("created_at" => "created_at"),
                binding!("updated_at" => "updated_at"),
            ],
            Self::ComplianceRolePermission => ROLE_PERMISSION,
            Self::ComplianceGroup => &[
                binding!("group_id" => "id"|"group_id"),
                binding!("group_name" => "name"),
                binding!("name" => "name"),
                binding!("description" => "description"),
                binding!("source_type" => "source_type"),
                binding!("roles" => "roles"),
                binding!("created_at" => "created_at"),
                binding!("updated_at" => "updated_at"),
            ],
            Self::ComplianceGroupMember => &[
                binding!("group_id" => "group_id"),
                binding!("user_id" => "user_id"|"id"),
                binding!("email" => "email"),
                binding!("created_at" => "created_at"),
                binding!("updated_at" => "updated_at"),
            ],
            Self::ComplianceProject => PROJECT,
            Self::ComplianceProjectCollaborator => PROJECT_COLLABORATOR,
            Self::ComplianceOrganizationSetting => &[
                binding!("organization_uuid" => "organization_uuid"),
                binding!("setting_name" => "name"),
                binding!("setting_type" => "type"),
                binding!("setting_value" => "value"),
            ],
        }
    }
}

const REPORT: &[AttributeBinding] = &[
    binding!("start_time" => "start_time"|"starting_at"|"date"),
    binding!("end_time" => "end_time"|"ending_at"),
    binding!("workspace_id" => "workspace_id"),
    binding!("user_id" => "user_id"),
    binding!("api_key_id" => "api_key_id"),
    binding!("model" => "model"),
    binding!("cost_usd" => "cost_usd"|"cost"),
    binding!("input_tokens" => "input_tokens"),
    binding!("output_tokens" => "output_tokens"),
    binding!("request_count" => "request_count"|"requests"),
    binding!("organization_id" => "organization_id"),
];

const RATE_LIMIT: &[AttributeBinding] = &[
    binding!("rate_limit_id" => "id"),
    binding!("group_type" => "group_type"),
    binding!("name" => "name"),
    binding!("model" => "model"),
    binding!("models" => "models"),
    binding!("workspace_id" => "workspace_id"),
    binding!("limits" => "limits"),
    binding!("requests_per_minute" => "requests_per_minute"|"rpm"),
    binding!("tokens_per_minute" => "tokens_per_minute"|"tpm"),
    binding!("input_tokens" => "input_tokens"),
    binding!("output_tokens" => "output_tokens"),
    binding!("updated_at" => "updated_at"),
];

const SPEND_LIMIT: &[AttributeBinding] = &[
    binding!("spend_limit_id" => "spend_limit_id"|"id"),
    binding!("scope_type" => "scope.type"),
    binding!("user_id" => "scope.user_id"|"actor.user_id"),
    binding!("actor_email" => "actor.email_address"|"actor.email"),
    binding!("amount" => "amount"),
    binding!("currency" => "currency"),
    binding!("period" => "period"),
    binding!("source_type" => "source.type"),
    binding!("period_to_date_spend" => "period_to_date_spend"),
    binding!("created_at" => "created_at"),
    binding!("updated_at" => "updated_at"),
];

const SPEND_LIMIT_REQUEST: &[AttributeBinding] = &[
    binding!("request_id" => "id"),
    binding!("user_id" => "scope.user_id"|"actor.user_id"),
    binding!("actor_email" => "actor.email_address"|"actor.email"),
    binding!("status" => "status"),
    binding!("amount" => "amount"),
    binding!("currency" => "currency"),
    binding!("period" => "period"),
    binding!("created_at" => "created_at"),
    binding!("updated_at" => "updated_at"),
];

const COMPLIANCE_ACTIVITY: &[AttributeBinding] = &[
    binding!("activity_id" => "id"),
    binding!("activity_type" => "type"),
    binding!("organization_id" => "organization_id"),
    binding!("organization_uuid" => "organization_uuid"),
    binding!("actor_type" => "actor.type"),
    binding!("actor_user_id" => "actor.user_id"),
    binding!("actor_api_key_id" => "actor.api_key_id"),
    binding!("actor_admin_api_key_id" => "actor.admin_api_key_id"),
    binding!("actor_email" => "actor.email_address"|"actor.email"|"actor.unauthenticated_email_address"),
    binding!("actor_ip_address" => "actor.ip_address"),
    binding!("actor_user_agent" => "actor.user_agent"),
    binding!("actor_workos_event_id" => "actor.workos_event_id"),
    binding!("actor_directory_id" => "actor.directory_id"),
    binding!("actor_idp_connection_type" => "actor.idp_connection_type"),
    binding!("claude_chat_id" => "claude_chat_id"|"chat_id"|"chat.id"),
    binding!("claude_file_id" => "claude_file_id"|"file_id"|"file.id"),
    binding!("claude_project_id" => "claude_project_id"|"project_id"|"project.id"),
    binding!("file_id" => "claude_file_id"|"file_id"|"file.id"),
    binding!("filename" => "filename"|"file.name"),
    binding!("project_id" => "claude_project_id"|"project_id"|"project.id"),
    binding!("created_at" => "created_at"),
];

const ROLE_PERMISSION: &[AttributeBinding] = &[
    binding!("organization_uuid" => "organization_uuid"),
    binding!("role_id" => "role_id"),
    binding!("permission_id" => "id"|"permission_id"|"permission"|"name"),
    binding!("permission" => "permission"|"permission_id"|"id"|"name"),
    binding!("permission_name" => "name"|"permission"|"permission_id"|"id"),
    binding!("permission_description" => "description"),
    binding!("action" => "action"),
    binding!("resource_type" => "resource_type"|"resource"),
    binding!("scope" => "scope"),
    binding!("category" => "category"|"type"),
    binding!("created_at" => "created_at"),
    binding!("updated_at" => "updated_at"),
];

const PROJECT: &[AttributeBinding] = &[
    binding!("project_id" => "id"|"project_id"),
    binding!("name" => "name"|"title"),
    binding!("description" => "description"),
    binding!("organization_id" => "organization.id"|"organization_id"),
    binding!("organization_uuid" => "organization.uuid"|"organization_uuid"|"organization.id"|"organization_id"),
    binding!("creator_user_id" => "created_by.id"|"creator.id"|"owner.id"|"created_by_user_id"|"user_id"),
    binding!("creator_email" => "created_by.email"|"creator.email"|"owner.email"|"email"),
    binding!("status" => "status"),
    binding!("visibility" => "visibility"),
    binding!("created_at" => "created_at"),
    binding!("updated_at" => "updated_at"),
    binding!("archived_at" => "archived_at"),
];

const PROJECT_COLLABORATOR: &[AttributeBinding] = &[
    binding!("project_id" => "project_id"),
    binding!("assignment_id" => "id"|"assignment_id"),
    binding!("principal_type" => "principal.type"|"principal_type"|"type"|"collaborator_type"),
    binding!("principal_id" => "principal.id"|"principal.user_id"|"principal.group_id"|"user.id"|"user_id"|"group.id"|"group_id"|"organization.id"|"organization_uuid"|"organization_id"|"id"),
    binding!("user_id" => "user.id"|"user_id"|"principal.user_id"|"principal.id"),
    binding!("group_id" => "group.id"|"group_id"|"principal.group_id"),
    binding!("email" => "principal.email"|"user.email"|"email"),
    binding!("name" => "principal.name"|"user.name"|"group.name"|"name"),
    binding!("organization_id" => "organization.id"|"organization_id"),
    binding!("organization_uuid" => "organization.uuid"|"organization_uuid"|"organization.id"|"organization_id"),
    binding!("role_id" => "role.id"|"role_id"|"role"),
    binding!("role" => "role.name"|"role.id"|"role_id"),
    binding!("role_name" => "role.name"|"role_name"|"role.id"|"role_id"),
    binding!("created_at" => "created_at"),
    binding!("updated_at" => "updated_at"),
];
