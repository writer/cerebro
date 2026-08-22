use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{
    GitHubError, GitHubKernel,
    normalize::{
        Normalized, insert_optional, positive_i64, required_string, scalar_at, string_at,
        timestamp_optional, value_at,
    },
};

pub(super) fn normalize_inventory(
    kernel: &GitHubKernel,
    stage: &str,
    values: &Map<String, Value>,
    observed_at: Option<&str>,
) -> Result<Normalized, GitHubError> {
    let occurred_at = parse_observation(observed_at)?;
    match stage {
        "members" => member(kernel, values, "member", occurred_at),
        "outside_collaborators" => member(kernel, values, "outside_collaborator", occurred_at),
        "installations" => installation(kernel, values, occurred_at),
        _ => Err(GitHubError::RequestScopeMismatch),
    }
}

fn member(
    kernel: &GitHubKernel,
    values: &Map<String, Value>,
    role: &str,
    occurred_at: String,
) -> Result<Normalized, GitHubError> {
    let login = required_string(values, "login")?;
    let id = positive_i64(values, "id")?;
    let payload = Value::Object(Map::from_iter([
        ("login".to_owned(), Value::from(login.clone())),
        ("id".to_owned(), Value::from(id)),
        ("role".to_owned(), Value::from(role)),
        ("org".to_owned(), Value::from(kernel.owner.clone())),
        (
            "avatar_url".to_owned(),
            Value::from(string_at(values, "avatar_url").unwrap_or_default()),
        ),
        (
            "html_url".to_owned(),
            Value::from(string_at(values, "html_url").unwrap_or_default()),
        ),
    ]));
    let attributes = BTreeMap::from([
        ("family".to_owned(), "org_inventory".to_owned()),
        ("login".to_owned(), login.clone()),
        ("owner".to_owned(), kernel.owner.clone()),
        ("role".to_owned(), role.to_owned()),
        ("user_id".to_owned(), id.to_string()),
    ]);
    Ok((
        "github.org_member",
        "github/org_member/v1",
        format!("{role}:{login}"),
        occurred_at,
        attributes,
        payload,
    ))
}

fn installation(
    kernel: &GitHubKernel,
    values: &Map<String, Value>,
    occurred_at: String,
) -> Result<Normalized, GitHubError> {
    let id = positive_i64(values, "id")?;
    let app_slug = required_string(values, "app_slug")?;
    let permissions = permission_pairs(values)?;
    let events = string_array(values, "events")?;
    let created_at = timestamp_optional(values, "created_at")?;
    let updated_at = timestamp_optional(values, "updated_at")?;
    let mut payload = Map::from_iter([
        ("id".to_owned(), Value::from(id)),
        ("app_slug".to_owned(), Value::from(app_slug.clone())),
        ("org".to_owned(), Value::from(kernel.owner.clone())),
    ]);
    insert_optional(
        &mut payload,
        "target_type",
        string_at(values, "target_type"),
    );
    insert_optional(
        &mut payload,
        "repository_selection",
        string_at(values, "repository_selection"),
    );
    if !permissions.is_empty() {
        payload.insert(
            "permissions".to_owned(),
            Value::Array(permissions.iter().cloned().map(Value::from).collect()),
        );
    }
    if !events.is_empty() {
        payload.insert(
            "events".to_owned(),
            Value::Array(events.iter().cloned().map(Value::from).collect()),
        );
    }
    insert_optional(&mut payload, "created_at", created_at.clone());
    insert_optional(&mut payload, "updated_at", updated_at.clone());
    let mut attributes = BTreeMap::from([
        ("app_slug".to_owned(), app_slug),
        ("events".to_owned(), events.join(",")),
        ("family".to_owned(), "org_inventory".to_owned()),
        ("installation_id".to_owned(), id.to_string()),
        ("owner".to_owned(), kernel.owner.clone()),
        ("permissions".to_owned(), permissions.join(",")),
    ]);
    for (source, target) in [
        ("repository_selection", "repository_selection"),
        ("target_type", "target_type"),
    ] {
        if let Some(value) = scalar_at(values, source) {
            attributes.insert(target.to_owned(), value);
        }
    }
    if let Some(value) = created_at {
        attributes.insert("created_at".to_owned(), value);
    }
    if let Some(value) = updated_at {
        attributes.insert("updated_at".to_owned(), value);
    }
    Ok((
        "github.org_installation",
        "github/org_installation/v1",
        id.to_string(),
        occurred_at,
        attributes,
        Value::Object(payload),
    ))
}

fn permission_pairs(values: &Map<String, Value>) -> Result<Vec<String>, GitHubError> {
    let Some(permissions) = value_at(values, "permissions") else {
        return Ok(Vec::new());
    };
    let permissions = permissions
        .as_object()
        .ok_or(GitHubError::InvalidProviderRecord)?;
    if permissions.len() > 100 {
        return Err(GitHubError::InvalidProviderRecord);
    }
    let mut result = permissions
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|level| format!("{name}:{level}"))
                .ok_or(GitHubError::InvalidProviderRecord)
        })
        .collect::<Result<Vec<_>, _>>()?;
    result.sort();
    Ok(result)
}

fn string_array(values: &Map<String, Value>, path: &str) -> Result<Vec<String>, GitHubError> {
    let Some(values) = value_at(values, path) else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .ok_or(GitHubError::InvalidProviderRecord)?;
    if values.len() > 250 {
        return Err(GitHubError::InvalidProviderRecord);
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or(GitHubError::InvalidProviderRecord)
        })
        .collect()
}

fn parse_observation(value: Option<&str>) -> Result<String, GitHubError> {
    let value = value.ok_or(GitHubError::MissingConfiguration("observed_at"))?;
    let map = Map::from_iter([("value".to_owned(), Value::from(value))]);
    super::normalize::timestamp_optional(&map, "value")?.ok_or(GitHubError::InvalidProviderRecord)
}
