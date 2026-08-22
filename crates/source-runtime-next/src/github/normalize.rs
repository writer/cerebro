use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    GitHubActorResolution, GitHubError, GitHubFamily, GitHubKernel, GitHubRecord,
    normalize_audit::normalize_audit,
    normalize_inventory::normalize_inventory,
    normalize_security::{normalize_dependabot, normalize_secret_scanning},
};

pub(super) fn normalize_record(
    kernel: &GitHubKernel,
    stage: &str,
    raw: Value,
    observed_at: Option<&str>,
    actors: &[GitHubActorResolution],
) -> Result<GitHubRecord, GitHubError> {
    if contains_key_recursive(&raw, "tenant_id") {
        return Err(GitHubError::TenantMismatch);
    }
    let values = raw.as_object().ok_or(GitHubError::InvalidProviderRecord)?;
    let (kind, schema_ref, provider_id, occurred_at, attributes, payload) = match kernel.family {
        GitHubFamily::Audit => normalize_audit(kernel, values, &raw, actors)?,
        GitHubFamily::Repository => normalize_repository(kernel, values)?,
        GitHubFamily::PullRequest => normalize_pull_request(kernel, values)?,
        GitHubFamily::DependabotAlert => normalize_dependabot(kernel, values)?,
        GitHubFamily::SecretScanningAlert => normalize_secret_scanning(kernel, values)?,
        GitHubFamily::OrganizationInventory => {
            normalize_inventory(kernel, stage, values, observed_at)?
        }
    };
    let definition = super::GitHubRuntimeDefinition::compile(kernel.family)?;
    let contract = definition
        .contract_for_kind(kind)
        .ok_or(GitHubError::EventContractRejection)?;
    if contract.schema_ref != schema_ref
        || contract.required_attributes.iter().any(|key| {
            attributes
                .get(*key)
                .is_none_or(|value| value.trim().is_empty())
        })
        || contract.required_payload_fields.iter().any(|key| {
            payload
                .get(*key)
                .is_none_or(|value| value.is_null() || value.as_str().is_some_and(str::is_empty))
        })
    {
        return Err(GitHubError::EventContractRejection);
    }
    let scope = Sha256::digest(format!(
        "{}\0{}\0{}\0{}",
        kernel.tenant_id, kind, provider_id, occurred_at
    ));
    let digest = scope[..10]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(GitHubRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: format!(
            "github-{}-{}-{digest}",
            normalized_id(&kernel.tenant_id),
            normalized_id(kernel.family.as_str())
        ),
        source_id: "github".to_owned(),
        kind: kind.to_owned(),
        schema_ref: schema_ref.to_owned(),
        family: kernel.family.as_str().to_owned(),
        provider_id,
        occurred_at,
        attributes,
        payload,
    })
}

pub(super) type Normalized = (
    &'static str,
    &'static str,
    String,
    String,
    BTreeMap<String, String>,
    Value,
);

fn normalize_repository(
    kernel: &GitHubKernel,
    values: &Map<String, Value>,
) -> Result<Normalized, GitHubError> {
    let name = required_string(values, "name")?;
    let owner_login = string_at(values, "owner.login")
        .or_else(|| {
            string_at(values, "full_name")
                .and_then(|value| value.split_once('/').map(|v| v.0.to_owned()))
        })
        .unwrap_or_else(|| kernel.owner.clone());
    let full_name =
        string_at(values, "full_name").unwrap_or_else(|| format!("{owner_login}/{name}"));
    let provider_id = scalar_at(values, "id").unwrap_or_else(|| full_name.clone());
    if provider_id.trim().is_empty() {
        return Err(GitHubError::MissingStableIdentity);
    }
    let occurred_at = timestamp_first(values, &["updated_at", "pushed_at", "created_at"])?;
    let created_at =
        timestamp_optional(values, "created_at")?.unwrap_or_else(|| occurred_at.clone());
    let mut payload = Map::new();
    insert_number(&mut payload, "id", values.get("id"));
    insert(&mut payload, "owner_login", owner_login.clone());
    insert(&mut payload, "name", name.clone());
    insert(&mut payload, "full_name", full_name.clone());
    insert_optional(&mut payload, "url", string_at(values, "html_url"));
    insert_optional(&mut payload, "visibility", string_at(values, "visibility"));
    insert_bool(&mut payload, "private", bool_at(values, "private"));
    insert_bool(&mut payload, "archived", bool_at(values, "archived"));
    insert_bool(&mut payload, "fork", bool_at(values, "fork"));
    insert_optional(
        &mut payload,
        "default_branch",
        string_at(values, "default_branch"),
    );
    insert(&mut payload, "created_at", created_at);
    insert(&mut payload, "updated_at", occurred_at.clone());
    insert_optional(
        &mut payload,
        "pushed_at",
        timestamp_optional(values, "pushed_at")?,
    );
    let security = [
        (
            "secret_scanning_enabled",
            "security_and_analysis.secret_scanning.status",
        ),
        (
            "secret_scanning_push_protection",
            "security_and_analysis.secret_scanning_push_protection.status",
        ),
        (
            "dependabot_security_updates_enabled",
            "security_and_analysis.dependabot_security_updates.status",
        ),
    ];
    for (target, source) in security {
        insert_optional(&mut payload, target, string_at(values, source));
    }
    let mut attributes = BTreeMap::from([
        (
            "archived".to_owned(),
            bool_at(values, "archived").to_string(),
        ),
        ("fork".to_owned(), bool_at(values, "fork").to_string()),
        ("full_name".to_owned(), full_name.clone()),
        ("name".to_owned(), name.clone()),
        ("owner".to_owned(), kernel.owner.clone()),
        ("owner_login".to_owned(), owner_login),
        ("private".to_owned(), bool_at(values, "private").to_string()),
        ("repo".to_owned(), name),
        ("repository".to_owned(), full_name.clone()),
        ("resource_id".to_owned(), provider_id.clone()),
        ("resource_name".to_owned(), full_name),
        ("resource_type".to_owned(), "code_repository".to_owned()),
    ]);
    copy(&mut attributes, values, "default_branch", "default_branch");
    copy(&mut attributes, values, "html_url", "html_url");
    copy(&mut attributes, values, "id", "repo_id");
    copy(&mut attributes, values, "visibility", "visibility");
    for (attribute, source) in [
        ("secret_scanning", security[0].1),
        ("secret_scanning_push_protection", security[1].1),
        ("dependabot_security_updates", security[2].1),
    ] {
        copy(&mut attributes, values, source, attribute);
    }
    Ok((
        "github.code.repository",
        "github/code_repository/v1",
        provider_id,
        occurred_at,
        attributes,
        Value::Object(payload),
    ))
}

fn normalize_pull_request(
    kernel: &GitHubKernel,
    values: &Map<String, Value>,
) -> Result<Normalized, GitHubError> {
    let number = positive_i64(values, "number")?;
    let provider_id = number.to_string();
    let occurred_at = timestamp_first(values, &["updated_at", "created_at"])?;
    let repository = format!(
        "{}/{}",
        kernel.owner,
        kernel.repository.as_deref().unwrap_or_default()
    );
    let created_at =
        timestamp_optional(values, "created_at")?.unwrap_or_else(|| occurred_at.clone());
    let author = string_at(values, "user.login").unwrap_or_default();
    let head = string_at(values, "head.label").unwrap_or_default();
    let base = string_at(values, "base.label").unwrap_or_default();
    let state = required_string(values, "state")?;
    let url = string_at(values, "html_url").unwrap_or_default();
    let mut payload = Map::from_iter([
        ("number".to_owned(), Value::from(number)),
        ("repository".to_owned(), Value::from(repository.clone())),
        (
            "title".to_owned(),
            Value::from(string_at(values, "title").unwrap_or_default()),
        ),
        ("state".to_owned(), Value::from(state.clone())),
        ("url".to_owned(), Value::from(url.clone())),
        ("author".to_owned(), Value::from(author.clone())),
        ("draft".to_owned(), Value::from(bool_at(values, "draft"))),
        ("head".to_owned(), Value::from(head.clone())),
        ("base".to_owned(), Value::from(base.clone())),
        ("created_at".to_owned(), Value::from(created_at)),
        ("updated_at".to_owned(), Value::from(occurred_at.clone())),
    ]);
    insert_optional(
        &mut payload,
        "closed_at",
        timestamp_optional(values, "closed_at")?,
    );
    insert_optional(
        &mut payload,
        "merged_at",
        timestamp_optional(values, "merged_at")?,
    );
    let attributes = BTreeMap::from([
        ("author".to_owned(), author),
        ("base".to_owned(), base),
        ("head".to_owned(), head),
        ("html_url".to_owned(), url),
        ("owner".to_owned(), kernel.owner.clone()),
        ("pull_number".to_owned(), provider_id.clone()),
        (
            "repo".to_owned(),
            kernel.repository.clone().unwrap_or_default(),
        ),
        ("repository".to_owned(), repository),
        ("state".to_owned(), state),
    ]);
    Ok((
        "github.pull_request",
        "github/pull_request/v1",
        provider_id,
        occurred_at,
        attributes,
        Value::Object(payload),
    ))
}

pub(super) fn required_string(
    values: &Map<String, Value>,
    path: &str,
) -> Result<String, GitHubError> {
    string_at(values, path).ok_or(GitHubError::InvalidProviderRecord)
}

pub(super) fn positive_i64(values: &Map<String, Value>, path: &str) -> Result<i64, GitHubError> {
    value_at(values, path)
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or(GitHubError::MissingStableIdentity)
}

pub(super) fn value_at<'a>(values: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut value = values.get(path.split('.').next()?)?;
    for part in path.split('.').skip(1) {
        value = value.as_object()?.get(part)?;
    }
    Some(value)
}

pub(super) fn string_at(values: &Map<String, Value>, path: &str) -> Option<String> {
    value_at(values, path)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn scalar_at(values: &Map<String, Value>, path: &str) -> Option<String> {
    match value_at(values, path)? {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub(super) fn bool_at(values: &Map<String, Value>, path: &str) -> bool {
    value_at(values, path)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(super) fn timestamp_first(
    values: &Map<String, Value>,
    paths: &[&str],
) -> Result<String, GitHubError> {
    for path in paths {
        if let Some(value) = timestamp_optional(values, path)? {
            return Ok(value);
        }
    }
    Err(GitHubError::InvalidProviderRecord)
}

pub(super) fn timestamp_optional(
    values: &Map<String, Value>,
    path: &str,
) -> Result<Option<String>, GitHubError> {
    let Some(value) = value_at(values, path) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let stamp = match value {
        Value::String(value) => OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| GitHubError::InvalidProviderRecord)?,
        Value::Number(value) => {
            let millis = value.as_i64().ok_or(GitHubError::InvalidProviderRecord)?;
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
                .map_err(|_| GitHubError::InvalidProviderRecord)?
        }
        _ => return Err(GitHubError::InvalidProviderRecord),
    };
    stamp
        .format(&Rfc3339)
        .map(Some)
        .map_err(|_| GitHubError::InvalidProviderRecord)
}

pub(super) fn insert(map: &mut Map<String, Value>, key: &str, value: String) {
    map.insert(key.to_owned(), Value::String(value));
}

pub(super) fn insert_optional(map: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        insert(map, key, value);
    }
}

pub(super) fn insert_bool(map: &mut Map<String, Value>, key: &str, value: bool) {
    map.insert(key.to_owned(), Value::Bool(value));
}

fn insert_number(map: &mut Map<String, Value>, key: &str, value: Option<&Value>) {
    if let Some(Value::Number(value)) = value.filter(|value| value.as_i64().is_some_and(|v| v != 0))
    {
        map.insert(key.to_owned(), Value::Number(value.clone()));
    }
}

pub(super) fn copy(
    attributes: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    source: &str,
    target: &str,
) {
    if let Some(value) = scalar_at(values, source) {
        attributes.insert(target.to_owned(), value);
    }
}

pub(super) fn normalized_id(value: &str) -> String {
    value
        .trim()
        .chars()
        .map(|character| match character {
            '/' | ':' | ' ' | '\t' | '\n' => '-',
            other => other,
        })
        .collect()
}

fn contains_key_recursive(value: &Value, forbidden: &str) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            key.eq_ignore_ascii_case(forbidden) || contains_key_recursive(value, forbidden)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_key_recursive(value, forbidden)),
        _ => false,
    }
}
