//! Closed OpenAI family contracts shared by request planning and decoding.

use super::OpenAiError;

pub(super) const SOURCE_ID: &str = "openai";
pub(super) const ORIGIN: &str = "https://api.openai.com";
pub(super) const BASE_PATH: &str = "/v1";
pub(super) const MAX_RESPONSE_BYTES: usize = 8 << 20;
pub(super) const MAX_RECORDS_PER_PAGE: usize = 10_000;
pub(super) const DEFAULT_PAGE_SIZE: usize = 100;
pub(super) const MAX_PAGE_SIZE: usize = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Pagination {
    Cursor,
    Page,
    None,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct FamilySpec {
    pub(super) id: &'static str,
    pub(super) path: &'static str,
    pub(super) path_parameters: &'static [&'static str],
    pub(super) pagination: Pagination,
    pub(super) id_paths: &'static [&'static str],
    pub(super) timestamp_paths: &'static [&'static str],
    pub(super) attributes: &'static [(&'static str, &'static str)],
    pub(super) required_attributes: &'static [&'static str],
    pub(super) required_payload_fields: &'static [&'static str],
    pub(super) allowed_query: &'static [(&'static str, &'static str)],
    pub(super) singleton_identity: Option<&'static str>,
}

/// One family in the closed OpenAI organization-governance runtime table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenAiFamily(&'static FamilySpec);

impl OpenAiFamily {
    /// Parse an exact OpenAI family identifier.
    pub fn parse(value: &str) -> Result<Self, OpenAiError> {
        FAMILY_SPECS
            .iter()
            .find(|spec| spec.id == value)
            .map(Self)
            .ok_or(OpenAiError::UnknownFamily)
    }

    /// Return every supported family in stable catalog order.
    pub fn all() -> impl ExactSizeIterator<Item = Self> {
        FAMILY_SPECS.iter().map(Self)
    }

    /// Return the exact source-catalog family identifier.
    pub fn id(self) -> &'static str {
        self.0.id
    }

    /// Return the exact emitted event kind.
    pub fn event_kind(self) -> String {
        format!("{SOURCE_ID}.{}", self.id())
    }

    /// Return the exact emitted event schema.
    pub fn schema_ref(self) -> String {
        format!("{SOURCE_ID}/{}/v1", self.id())
    }

    pub(super) fn spec(self) -> &'static FamilySpec {
        self.0
    }
}

const STANDARD_QUERY: &[(&str, &str)] = &[];
const AUDIT_QUERY: &[(&str, &str)] = &[
    ("actor_emails", "actor_emails"),
    ("actor_ids", "actor_ids"),
    ("effective_at_gt", "effective_at[gt]"),
    ("effective_at_gte", "effective_at[gte]"),
    ("effective_at_lt", "effective_at[lt]"),
    ("effective_at_lte", "effective_at[lte]"),
    ("event_types", "event_types"),
    ("project_ids", "project_ids"),
    ("resource_ids", "resource_ids"),
    ("tenant_only", "tenant_only"),
];
const USAGE_QUERY: &[(&str, &str)] = &[
    ("api_key_ids", "api_key_ids"),
    ("batch", "batch"),
    ("bucket_width", "bucket_width"),
    ("end_time", "end_time"),
    ("group_by", "group_by"),
    ("models", "models"),
    ("project_ids", "project_ids"),
    ("start_time", "start_time"),
    ("user_ids", "user_ids"),
];

const USER_ATTRS: &[(&str, &str)] = &[
    ("user_id", "id"),
    ("name", "name"),
    ("email", "email"),
    ("role", "role"),
    ("status", "status"),
    ("added_at", "added_at"),
];
const PROJECT_ATTRS: &[(&str, &str)] = &[
    ("project_id", "id"),
    ("name", "name"),
    ("status", "status"),
    ("created_at", "created_at"),
    ("archived_at", "archived_at"),
    ("external_key_id", "external_key_id"),
];
const SERVICE_ACCOUNT_ATTRS: &[(&str, &str)] = &[
    ("service_account_id", "id"),
    ("project_id", "project_id"),
    ("name", "name"),
    ("role", "role"),
    ("created_at", "created_at"),
];
const API_KEY_ATTRS: &[(&str, &str)] = &[
    ("api_key_id", "id"),
    ("project_id", "project_id"),
    ("name", "name"),
    ("owner_user_id", "owner.user.id"),
    ("owner_service_account_id", "owner.service_account.id"),
    ("owner_type", "owner.type"),
    ("status", "status"),
    ("created_at", "created_at"),
    ("last_used_at", "last_used_at"),
];
const ADMIN_KEY_ATTRS: &[(&str, &str)] = &[
    ("api_key_id", "id"),
    ("name", "name"),
    ("owner_id", "owner.id"),
    ("owner_name", "owner.name"),
    ("owner_object", "owner.object"),
    ("owner_role", "owner.role"),
    ("owner_type", "owner.type"),
    ("status", "status"),
    ("created_at", "created_at"),
    ("last_used_at", "last_used_at"),
];
const INVITE_ATTRS: &[(&str, &str)] = &[
    ("invite_id", "id"),
    ("email", "email"),
    ("role", "role"),
    ("status", "status"),
    ("projects", "projects"),
    ("created_at", "created_at"),
    ("accepted_at", "accepted_at"),
    ("expires_at", "expires_at"),
];
const ROLE_ATTRS: &[(&str, &str)] = &[
    ("role_id", "id"),
    ("name", "name"),
    ("description", "description"),
    ("permissions", "permissions"),
    ("resource_type", "resource_type"),
    ("predefined_role", "predefined_role"),
    ("created_at", "created_at"),
    ("updated_at", "updated_at"),
    ("created_by", "created_by"),
];
const GROUP_ATTRS: &[(&str, &str)] = &[
    ("group_id", "id"),
    ("name", "name"),
    ("created_at", "created_at"),
    ("updated_at", "updated_at"),
];
const MEMBER_ATTRS: &[(&str, &str)] = &[
    ("user_id", "id|user_id"),
    ("email", "email"),
    ("name", "name"),
    ("role", "role"),
    ("added_at", "added_at"),
];
const RETENTION_ATTRS: &[(&str, &str)] = &[("retention_type", "type"), ("object", "object")];
const SPEND_ATTRS: &[(&str, &str)] = &[
    ("spend_alert_id", "id"),
    ("name", "name"),
    ("status", "status"),
    ("threshold", "threshold"),
    ("threshold_amount", "threshold_amount"),
    ("created_at", "created_at"),
    ("updated_at", "updated_at"),
];
const CERT_ATTRS: &[(&str, &str)] = &[
    ("certificate_id", "id"),
    ("name", "name"),
    ("active", "active"),
    ("created_at", "created_at"),
    ("valid_at", "certificate_details.valid_at"),
    ("expires_at", "certificate_details.expires_at"),
];
const USAGE_ATTRS: &[(&str, &str)] = &[
    ("start_time", "start_time"),
    ("end_time", "end_time"),
    ("result_count", "results.__count"),
    ("input_tokens", "results.input_tokens.__sum|input_tokens"),
    ("output_tokens", "results.output_tokens.__sum|output_tokens"),
    (
        "num_model_requests",
        "results.num_model_requests.__sum|num_model_requests",
    ),
    ("project_id", "project_id"),
    ("user_id", "user_id"),
    ("api_key_id", "api_key_id"),
    ("model", "model"),
    ("line_item", "line_item"),
    ("amount_value", "amount.value|amount"),
    ("amount_currency", "amount.currency"),
    ("organization_object", "object"),
];
const RATE_LIMIT_ATTRS: &[(&str, &str)] = &[
    ("rate_limit_id", "id"),
    ("model", "model"),
    ("created_at", "created_at"),
    ("updated_at", "updated_at"),
    ("max_requests_per_1_minute", "max_requests_per_1_minute"),
    ("max_tokens_per_1_minute", "max_tokens_per_1_minute"),
    ("max_images_per_1_minute", "max_images_per_1_minute"),
    ("max_requests_per_1_day", "max_requests_per_1_day"),
    (
        "batch_1_day_max_input_tokens",
        "batch_1_day_max_input_tokens",
    ),
];
const MODEL_PERMISSION_ATTRS: &[(&str, &str)] = &[("mode", "mode"), ("model_ids", "model_ids")];
const TOOL_PERMISSION_ATTRS: &[(&str, &str)] = &[
    ("code_interpreter_enabled", "code_interpreter.enabled"),
    ("file_search_enabled", "file_search.enabled"),
    ("image_generation_enabled", "image_generation.enabled"),
    ("mcp_enabled", "mcp.enabled"),
    ("web_search_enabled", "web_search.enabled"),
];
const AUDIT_ATTRS: &[(&str, &str)] = &[
    (
        "api_key_id",
        "api_key.created.id|api_key.updated.id|api_key.deleted.id|api_key.id|api_key_id",
    ),
    ("audit_log_id", "id"),
    ("actor_api_key_id", "actor.api_key.id"),
    ("actor_city", "actor.session.ip_address_details.city"),
    ("actor_country", "actor.session.ip_address_details.country"),
    (
        "actor_email",
        "actor.session.user.email|actor.api_key.user.email|actor.user.email|actor.email",
    ),
    (
        "actor_id",
        "actor.session.user.id|actor.api_key.user.id|actor.api_key.service_account.id|actor.api_key.id|actor.user.id|actor.service_account.id|actor.id",
    ),
    ("actor_ip_address", "actor.session.ip_address"),
    ("actor_region", "actor.session.ip_address_details.region"),
    (
        "actor_service_account_id",
        "actor.api_key.service_account.id|actor.service_account.id",
    ),
    ("actor_type", "actor.type|actor.api_key.type"),
    ("actor_user_agent", "actor.session.user_agent"),
    (
        "actor_user_id",
        "actor.session.user.id|actor.api_key.user.id|actor.user.id",
    ),
    (
        "certificate_id",
        "certificate.created.id|certificate.updated.id|certificate.deleted.id",
    ),
    (
        "certificate_name",
        "certificate.created.name|certificate.updated.name|certificate.deleted.name",
    ),
    ("effective_at", "effective_at"),
    ("event_type", "type|event_type"),
    (
        "external_key_id",
        "external_key.registered.id|external_key.removed.id",
    ),
    (
        "group_id",
        "group.created.id|group.updated.id|group.deleted.id",
    ),
    (
        "group_name",
        "group.created.data.group_name|group.updated.changes_requested.group_name",
    ),
    ("invite_email", "invite.sent.data.email"),
    (
        "invite_id",
        "invite.sent.id|invite.accepted.id|invite.deleted.id",
    ),
    ("invite_role", "invite.sent.data.role"),
    (
        "ip_allowlist_id",
        "ip_allowlist.created.id|ip_allowlist.updated.id|ip_allowlist.deleted.id",
    ),
    (
        "ip_allowlist_name",
        "ip_allowlist.created.name|ip_allowlist.deleted.name",
    ),
    (
        "organization_id",
        "organization.updated.id|organization_id|org_id",
    ),
    (
        "principal_id",
        "role.assignment.created.principal_id|role.assignment.deleted.principal_id",
    ),
    (
        "principal_type",
        "role.assignment.created.principal_type|role.assignment.deleted.principal_type",
    ),
    (
        "project_id",
        "project.created.id|project.updated.id|project.archived.id|project.deleted.id|checkpoint.permission.created.data.project_id|project.id|project_id",
    ),
    (
        "rate_limit_id",
        "rate_limit.updated.id|rate_limit.deleted.id",
    ),
    (
        "resource_id",
        "role.assignment.created.resource_id|role.assignment.deleted.resource_id|role.bound_to_resource.resource_id|role.unbound_from_resource.resource_id|resource.deleted.id",
    ),
    (
        "resource_type",
        "role.assignment.created.resource_type|role.assignment.deleted.resource_type|role.bound_to_resource.resource_type|role.unbound_from_resource.resource_type|resource.deleted.type",
    ),
    (
        "role_assignment_id",
        "role.assignment.created.id|role.assignment.deleted.id",
    ),
    (
        "role_id",
        "role.created.id|role.updated.id|role.deleted.id|role.bound_to_resource.role_id|role.unbound_from_resource.role_id",
    ),
    (
        "role_name",
        "role.created.data.role_name|role.updated.changes_requested.role_name|role.bound_to_resource.role_name|role.unbound_from_resource.role_name",
    ),
    (
        "service_account_id",
        "service_account.created.id|service_account.updated.id|service_account.deleted.id",
    ),
    ("user_id", "user.added.id|user.updated.id|user.deleted.id"),
];

macro_rules! family {
    ($id:literal, $path:literal, $params:expr, $pagination:expr, $ids:expr, $times:expr, $attrs:expr, $required:expr, $payload:expr, $query:expr, $singleton:expr) => {
        FamilySpec {
            id: $id,
            path: $path,
            path_parameters: $params,
            pagination: $pagination,
            id_paths: $ids,
            timestamp_paths: $times,
            attributes: $attrs,
            required_attributes: $required,
            required_payload_fields: $payload,
            allowed_query: $query,
            singleton_identity: $singleton,
        }
    };
}

const FAMILY_SPECS: &[FamilySpec] = &[
    family!(
        "user",
        "/organization/users",
        &[],
        Pagination::Cursor,
        &["id"],
        &["added_at"],
        USER_ATTRS,
        &["user_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "project",
        "/organization/projects",
        &[],
        Pagination::Cursor,
        &["id"],
        &["created_at"],
        PROJECT_ATTRS,
        &["project_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "service_account",
        "/organization/projects/default/service_accounts",
        &[],
        Pagination::Cursor,
        &["id"],
        &["created_at"],
        SERVICE_ACCOUNT_ATTRS,
        &["service_account_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "api_key",
        "/organization/projects/default/api_keys",
        &[],
        Pagination::Cursor,
        &["id"],
        &["created_at", "last_used_at"],
        API_KEY_ATTRS,
        &["api_key_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "admin_api_key",
        "/organization/admin_api_keys",
        &[],
        Pagination::Cursor,
        &["id"],
        &["created_at", "last_used_at"],
        ADMIN_KEY_ATTRS,
        &["api_key_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "audit_log",
        "/organization/audit_logs",
        &[],
        Pagination::Cursor,
        &["id"],
        &["effective_at", "created_at"],
        AUDIT_ATTRS,
        &["audit_log_id"],
        &["id"],
        AUDIT_QUERY,
        None
    ),
    family!(
        "invite",
        "/organization/invites",
        &[],
        Pagination::Cursor,
        &["id"],
        &["created_at"],
        INVITE_ATTRS,
        &["invite_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "role",
        "/organization/roles",
        &[],
        Pagination::Cursor,
        &["id"],
        &["created_at", "updated_at"],
        ROLE_ATTRS,
        &["role_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "user_role",
        "/organization/users/{user_id}/roles",
        &["user_id"],
        Pagination::Cursor,
        &["id"],
        &["created_at", "updated_at"],
        ROLE_ATTRS,
        &["role_id", "user_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "group",
        "/organization/groups",
        &[],
        Pagination::Cursor,
        &["id"],
        &["created_at", "updated_at"],
        GROUP_ATTRS,
        &["group_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "group_user",
        "/organization/groups/{group_id}/users",
        &["group_id"],
        Pagination::Cursor,
        &["id", "user_id"],
        &["added_at", "created_at"],
        MEMBER_ATTRS,
        &["group_id", "user_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "group_role",
        "/organization/groups/{group_id}/roles",
        &["group_id"],
        Pagination::Cursor,
        &["id"],
        &["created_at", "updated_at"],
        ROLE_ATTRS,
        &["group_id", "role_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "data_retention",
        "/organization/data_retention",
        &[],
        Pagination::None,
        &[],
        &[],
        RETENTION_ATTRS,
        &["external_id"],
        &[],
        STANDARD_QUERY,
        Some("organization:data_retention")
    ),
    family!(
        "spend_alert",
        "/organization/spend_alerts",
        &[],
        Pagination::Cursor,
        &["id"],
        &["created_at", "updated_at"],
        SPEND_ATTRS,
        &["spend_alert_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "certificate",
        "/organization/certificates",
        &[],
        Pagination::Cursor,
        &["id"],
        &["created_at", "certificate_details.expires_at"],
        CERT_ATTRS,
        &["certificate_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "usage_audio_speech",
        "/organization/usage/audio_speeches",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "usage_audio_transcription",
        "/organization/usage/audio_transcriptions",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "usage_code_interpreter_session",
        "/organization/usage/code_interpreter_sessions",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "usage_completion",
        "/organization/usage/completions",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "usage_embedding",
        "/organization/usage/embeddings",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "usage_image",
        "/organization/usage/images",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "usage_moderation",
        "/organization/usage/moderations",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "usage_vector_store",
        "/organization/usage/vector_stores",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "usage_file_search_call",
        "/organization/usage/file_search_calls",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "usage_web_search_call",
        "/organization/usage/web_search_calls",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "cost",
        "/organization/costs",
        &[],
        Pagination::Page,
        &["id"],
        &["start_time", "end_time"],
        USAGE_ATTRS,
        &["external_id"],
        &[],
        USAGE_QUERY,
        None
    ),
    family!(
        "project_user",
        "/organization/projects/{project_id}/users",
        &["project_id"],
        Pagination::Cursor,
        &["id", "user_id"],
        &["added_at"],
        MEMBER_ATTRS,
        &["project_id", "user_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "project_user_role",
        "/projects/{project_id}/users/{user_id}/roles",
        &["project_id", "user_id"],
        Pagination::Cursor,
        &["id"],
        &["created_at", "updated_at"],
        ROLE_ATTRS,
        &["project_id", "role_id", "user_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "project_service_account",
        "/organization/projects/{project_id}/service_accounts",
        &["project_id"],
        Pagination::Cursor,
        &["id"],
        &["created_at"],
        SERVICE_ACCOUNT_ATTRS,
        &["project_id", "service_account_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "project_api_key",
        "/organization/projects/{project_id}/api_keys",
        &["project_id"],
        Pagination::Cursor,
        &["id"],
        &["created_at", "last_used_at"],
        API_KEY_ATTRS,
        &["api_key_id", "project_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "project_rate_limit",
        "/organization/projects/{project_id}/rate_limits",
        &["project_id"],
        Pagination::Cursor,
        &["id", "model"],
        &["updated_at", "created_at"],
        RATE_LIMIT_ATTRS,
        &["external_id", "project_id"],
        &[],
        STANDARD_QUERY,
        None
    ),
    family!(
        "project_model_permission",
        "/organization/projects/{project_id}/model_permissions",
        &["project_id"],
        Pagination::None,
        &[],
        &[],
        MODEL_PERMISSION_ATTRS,
        &["external_id", "project_id"],
        &[],
        STANDARD_QUERY,
        Some("{project_id}:model_permissions")
    ),
    family!(
        "project_hosted_tool_permission",
        "/organization/projects/{project_id}/hosted_tool_permissions",
        &["project_id"],
        Pagination::None,
        &[],
        &[],
        TOOL_PERMISSION_ATTRS,
        &["external_id", "project_id"],
        &[],
        STANDARD_QUERY,
        Some("{project_id}:hosted_tool_permissions")
    ),
    family!(
        "project_group",
        "/organization/projects/{project_id}/groups",
        &["project_id"],
        Pagination::Cursor,
        &["id"],
        &["created_at", "updated_at"],
        GROUP_ATTRS,
        &["group_id", "project_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "project_group_role",
        "/organization/projects/{project_id}/groups/{group_id}/roles",
        &["project_id", "group_id"],
        Pagination::Cursor,
        &["id"],
        &["created_at", "updated_at"],
        ROLE_ATTRS,
        &["group_id", "project_id", "role_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "project_role",
        "/projects/{project_id}/roles",
        &["project_id"],
        Pagination::Cursor,
        &["id"],
        &["created_at", "updated_at"],
        ROLE_ATTRS,
        &["project_id", "role_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "project_data_retention",
        "/organization/projects/{project_id}/data_retention",
        &["project_id"],
        Pagination::None,
        &[],
        &[],
        RETENTION_ATTRS,
        &["external_id", "project_id"],
        &[],
        STANDARD_QUERY,
        Some("{project_id}:data_retention")
    ),
    family!(
        "project_spend_alert",
        "/organization/projects/{project_id}/spend_alerts",
        &["project_id"],
        Pagination::Cursor,
        &["id"],
        &["created_at", "updated_at"],
        SPEND_ATTRS,
        &["project_id", "spend_alert_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
    family!(
        "project_certificate",
        "/organization/projects/{project_id}/certificates",
        &["project_id"],
        Pagination::Cursor,
        &["id"],
        &["created_at", "certificate_details.expires_at"],
        CERT_ATTRS,
        &["certificate_id", "project_id"],
        &["id"],
        STANDARD_QUERY,
        None
    ),
];
