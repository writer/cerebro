use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{
    GitHubActorResolution, GitHubError, GitHubKernel,
    normalize::{
        Normalized, bool_at, normalized_id, required_string, scalar_at, string_at, timestamp_first,
        value_at,
    },
};

const EXTRA_ATTRIBUTES: &[&str] = &[
    "advanced_security_enabled",
    "allowed_cidrs_compliant",
    "allowlisted_destination",
    "auth_control_weakened",
    "branch",
    "bypass_actor_added",
    "change_type",
    "changes",
    "code_security_enabled",
    "deletions_allowed",
    "dependabot_alerts_enabled",
    "dependabot_enabled",
    "dependabot_security_updates_enabled",
    "destination_allowlisted",
    "destination_non_allowlisted",
    "enforcement",
    "ephemeral",
    "force_pushes_allowed",
    "github_advanced_security_enabled",
    "hook_destination_allowlisted",
    "hook_destination_non_allowlisted",
    "hook_id",
    "hook_url_allowlisted",
    "hook_url_non_allowlisted",
    "host_trusted",
    "host_untrusted",
    "integration",
    "ip_allow_list_disabled",
    "ip_allow_list_enabled",
    "ip_allow_list_entries_compliant",
    "is_ephemeral",
    "is_registered",
    "mfa_required",
    "name",
    "new_enforcement",
    "non_allowlisted_cidr_count",
    "non_allowlisted_cidrs",
    "non_allowlisted_destination",
    "number",
    "oauth_app_restrictions_enabled",
    "oauth_app_restrictions_enforced",
    "permission",
    "previous_visibility",
    "private_forking_enabled",
    "private_repository_forking_enabled",
    "registered",
    "repository_public",
    "repository_secret_scanning_enabled",
    "repository_vulnerability_alerts_enabled",
    "required_review_removed",
    "required_status_check_removed",
    "ruleset_enforcement",
    "ruleset_id",
    "ruleset_name",
    "runner_ephemeral",
    "runner_group_name",
    "runner_host_trusted",
    "runner_id",
    "runner_name",
    "runner_registered",
    "runner_scope",
    "runner_state",
    "runner_untrusted",
    "saml_enabled",
    "saml_enforced",
    "saml_provider_settings_weakened",
    "saml_required",
    "saml_sso_enabled",
    "secret_scanning_enabled",
    "secret_scanning_push_protection_enabled",
    "transport_protocol_name",
    "trusted_host",
    "two_factor_enforced",
    "two_factor_required",
    "two_factor_requirement_enabled",
    "untrusted_host",
    "url_allowlisted",
    "url_non_allowlisted",
    "user_agent",
    "vulnerability_alerts_enabled",
    "webhook_destination_allowlisted",
    "webhook_destination_non_allowlisted",
    "webhook_url_allowlisted",
    "webhook_url_non_allowlisted",
];

pub(super) fn normalize_audit(
    kernel: &GitHubKernel,
    values: &Map<String, Value>,
    raw: &Value,
    actors: &[GitHubActorResolution],
) -> Result<Normalized, GitHubError> {
    let action = required_string(values, "action")?;
    let occurred_at = timestamp_first(values, &["@timestamp", "created_at"])?;
    let actor = string_at(values, "actor").unwrap_or_default();
    let resolution = if actor.is_empty() {
        None
    } else {
        Some(
            actors
                .iter()
                .find(|item| item.actor == actor)
                .ok_or_else(|| GitHubError::ActorResolutionRequired {
                    actor: actor.clone(),
                })?,
        )
    };
    let org = string_at(values, "org").unwrap_or_else(|| kernel.owner.clone());
    let resource_id = resource_id(values, &org);
    let resource_type = resource_type(&action);
    let scope = scope(values, &org);
    let provider_id = string_at(values, "_document_id")
        .unwrap_or_else(|| format!("{}:{}", normalized_id(&action), occurred_at));
    let mut payload = Map::from_iter([
        ("action".to_owned(), Value::from(action.clone())),
        ("org".to_owned(), Value::from(org.clone())),
    ]);
    for (target, source) in [
        ("actor", "actor"),
        ("actor_ip", "actor_ip"),
        ("business", "business"),
        ("external_identity_nameid", "external_identity_nameid"),
        ("external_identity_username", "external_identity_username"),
        ("operation_type", "operation_type"),
        ("programmatic_access_type", "programmatic_access_type"),
        ("repo", "repo"),
        ("user", "user"),
        ("visibility", "visibility"),
    ] {
        insert_optional(&mut payload, target, string_at(values, source));
    }
    if let Some(resolution) = resolution {
        insert_optional(
            &mut payload,
            "actor_type",
            Some(resolution.actor_type.clone()),
        );
        insert_optional(&mut payload, "actor_email", resolution.actor_email.clone());
    }
    for (target, source) in [
        ("actor_id", "actor_id"),
        ("business_id", "business_id"),
        ("user_id", "user_id"),
    ] {
        let value = value_at(values, source)
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .or_else(|| {
                (target == "actor_id")
                    .then(|| resolution.and_then(|value| value.actor_id))
                    .flatten()
            });
        if let Some(value) = value {
            payload.insert(target.to_owned(), Value::from(value));
        }
    }
    for field in ["actor_is_agent", "actor_is_bot", "public_repo"] {
        if value_at(values, field).is_some() {
            payload.insert(field.to_owned(), Value::from(bool_at(values, field)));
        }
    }
    insert_optional(&mut payload, "resource_id", Some(resource_id.clone()));
    insert_optional(&mut payload, "resource_type", Some(resource_type.clone()));
    insert_optional(&mut payload, "scope", Some(scope.clone()));
    payload.insert("raw".to_owned(), normalized_raw(values, raw)?);
    let mut attributes = BTreeMap::from([
        ("action".to_owned(), action.clone()),
        ("family".to_owned(), "audit".to_owned()),
        (
            "operation_type".to_owned(),
            string_at(values, "operation_type").unwrap_or_default(),
        ),
        ("org".to_owned(), org),
        ("resource_id".to_owned(), resource_id),
        ("resource_type".to_owned(), resource_type),
        ("scope".to_owned(), scope),
    ]);
    for field in [
        "actor",
        "actor_id",
        "external_identity_nameid",
        "external_identity_username",
        "org_id",
        "programmatic_access_type",
        "repo",
        "token_id",
        "user",
        "user_id",
        "visibility",
    ] {
        if let Some(value) = scalar_at(values, field) {
            attributes.insert(field.to_owned(), value);
        }
    }
    if let Some(resolution) = resolution {
        attributes.insert("actor_type".to_owned(), resolution.actor_type.clone());
        if let Some(email) = &resolution.actor_email {
            attributes.insert("actor_email".to_owned(), email.clone());
        }
        if !attributes.contains_key("actor_id")
            && let Some(id) = resolution.actor_id.filter(|id| *id > 0)
        {
            attributes.insert("actor_id".to_owned(), id.to_string());
        }
    }
    for field in ["actor_is_agent", "actor_is_bot"] {
        if value_at(values, field).is_some() {
            attributes.insert(field.to_owned(), bool_at(values, field).to_string());
        }
    }
    if action.starts_with("integration_installation.")
        && let Some(value) = scalar_at(values, "installation.app_id")
            .or_else(|| scalar_at(values, "installation.id"))
    {
        attributes.insert("github_app_id".to_owned(), value);
    }
    if action.starts_with("secret_scanning_alert.") {
        for field in ["resolution", "state", "resolution_comment"] {
            let value = scalar_at(values, &format!("secret_scanning_alert.{field}"))
                .or_else(|| scalar_at(values, &format!("secret_scanning_alert.{field}")));
            if let Some(value) = value {
                attributes.insert(format!("secret_scanning_alert.{field}"), value);
            }
        }
    }
    for field in EXTRA_ATTRIBUTES {
        if let Some(value) = scalar_at(values, field) {
            attributes.insert((*field).to_owned(), value);
        }
    }
    Ok((
        "github.audit",
        "github/audit/v1",
        provider_id,
        occurred_at,
        attributes,
        Value::Object(payload),
    ))
}

fn resource_id(values: &Map<String, Value>, org: &str) -> String {
    for path in [
        "repo",
        "repository",
        "user",
        "actor",
        "hook_id",
        "token_id",
        "ruleset_id",
    ] {
        if let Some(value) = scalar_at(values, path) {
            return value;
        }
    }
    org.to_owned()
}

fn resource_type(action: &str) -> String {
    action
        .split_once('.')
        .map(|value| value.0)
        .filter(|value| !value.is_empty())
        .unwrap_or("organization")
        .to_owned()
}

fn scope(values: &Map<String, Value>, org: &str) -> String {
    if string_at(values, "repo").is_some() {
        "repository".to_owned()
    } else if string_at(values, "org").is_some() || !org.is_empty() {
        "organization".to_owned()
    } else {
        "enterprise".to_owned()
    }
}

fn insert_optional(map: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        map.insert(key.to_owned(), Value::from(value));
    }
}

fn normalized_raw(values: &Map<String, Value>, raw: &Value) -> Result<Value, GitHubError> {
    let mut normalized = raw
        .as_object()
        .cloned()
        .ok_or(GitHubError::InvalidProviderRecord)?;
    for key in ["@timestamp", "created_at"] {
        if value_at(values, key).is_some_and(Value::is_number)
            && let Some(value) = super::normalize::timestamp_optional(values, key)?
        {
            normalized.insert(key.to_owned(), Value::from(value));
        }
    }
    Ok(Value::Object(normalized))
}
