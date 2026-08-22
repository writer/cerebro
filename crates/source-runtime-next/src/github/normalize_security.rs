use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{
    GitHubError, GitHubKernel,
    normalize::{
        Normalized, bool_at, insert_optional, positive_i64, required_string, scalar_at, string_at,
        timestamp_first, timestamp_optional, value_at,
    },
};

pub(super) fn normalize_dependabot(
    kernel: &GitHubKernel,
    values: &Map<String, Value>,
) -> Result<Normalized, GitHubError> {
    let number = positive_i64(values, "number")?;
    let occurred_at = timestamp_first(values, &["updated_at", "created_at"])?;
    let created_at =
        timestamp_optional(values, "created_at")?.unwrap_or_else(|| occurred_at.clone());
    let repository = format!(
        "{}/{}",
        kernel.owner,
        kernel.repository.as_deref().unwrap_or_default()
    );
    let state = required_string(values, "state")?;
    let fields = [
        ("url", "url"),
        ("html_url", "html_url"),
        ("ghsa_id", "security_advisory.ghsa_id"),
        ("cve_id", "security_advisory.cve_id"),
        ("advisory_summary", "security_advisory.summary"),
        ("advisory_severity", "security_advisory.severity"),
        ("vulnerability_severity", "security_vulnerability.severity"),
        ("manifest_path", "dependency.manifest_path"),
        ("dependency_scope", "dependency.scope"),
        (
            "vulnerable_version_range",
            "security_vulnerability.vulnerable_version_range",
        ),
        (
            "first_patched_version",
            "security_vulnerability.first_patched_version.identifier",
        ),
        ("dismissed_by", "dismissed_by.login"),
    ];
    let ecosystem = string_at(values, "dependency.package.ecosystem")
        .or_else(|| string_at(values, "security_vulnerability.package.ecosystem"));
    let package = string_at(values, "dependency.package.name")
        .or_else(|| string_at(values, "security_vulnerability.package.name"));
    let mut payload = Map::from_iter([
        ("number".to_owned(), Value::from(number)),
        ("repository".to_owned(), Value::from(repository.clone())),
        ("state".to_owned(), Value::from(state.clone())),
        ("created_at".to_owned(), Value::from(created_at)),
        ("updated_at".to_owned(), Value::from(occurred_at.clone())),
    ]);
    for (target, source) in fields {
        insert_optional(&mut payload, target, string_at(values, source));
    }
    insert_optional(&mut payload, "ecosystem", ecosystem.clone());
    insert_optional(&mut payload, "package_name", package.clone());
    if let Some(id) = value_at(values, "dismissed_by.id")
        .and_then(Value::as_i64)
        .filter(|v| *v > 0)
    {
        payload.insert("dismissed_by_id".to_owned(), Value::from(id));
    }
    for field in ["dismissed_at", "fixed_at"] {
        insert_optional(&mut payload, field, timestamp_optional(values, field)?);
    }
    let severity = string_at(values, "security_advisory.severity")
        .or_else(|| string_at(values, "security_vulnerability.severity"))
        .unwrap_or_default();
    let mut attributes = BTreeMap::from([
        ("alert_number".to_owned(), number.to_string()),
        ("family".to_owned(), "dependabot_alert".to_owned()),
        ("owner".to_owned(), kernel.owner.clone()),
        (
            "repo".to_owned(),
            kernel.repository.clone().unwrap_or_default(),
        ),
        ("repository".to_owned(), repository),
        ("severity".to_owned(), severity),
        ("state".to_owned(), state),
        (
            "vulnerable_version_range".to_owned(),
            string_at(values, "security_vulnerability.vulnerable_version_range")
                .unwrap_or_default(),
        ),
    ]);
    for (target, source) in [
        ("advisory_cve_id", "security_advisory.cve_id"),
        ("advisory_ghsa_id", "security_advisory.ghsa_id"),
        ("advisory_severity", "security_advisory.severity"),
        ("dependency_scope", "dependency.scope"),
        ("dismissed_by", "dismissed_by.login"),
        ("dismissed_by_id", "dismissed_by.id"),
        (
            "first_patched_version",
            "security_vulnerability.first_patched_version.identifier",
        ),
        ("html_url", "html_url"),
        ("manifest_path", "dependency.manifest_path"),
        ("vulnerability_severity", "security_vulnerability.severity"),
    ] {
        if let Some(value) = scalar_at(values, source) {
            attributes.insert(target.to_owned(), value);
        }
    }
    if let Some(value) = ecosystem {
        attributes.insert("ecosystem".to_owned(), value);
    }
    if let Some(value) = package {
        attributes.insert("package".to_owned(), value);
    }
    Ok((
        "github.dependabot_alert",
        "github/dependabot_alert/v1",
        number.to_string(),
        occurred_at,
        attributes,
        Value::Object(payload),
    ))
}

pub(super) fn normalize_secret_scanning(
    kernel: &GitHubKernel,
    values: &Map<String, Value>,
) -> Result<Normalized, GitHubError> {
    let number = positive_i64(values, "number")?;
    let occurred_at = timestamp_first(values, &["updated_at", "created_at"])?;
    let created_at =
        timestamp_optional(values, "created_at")?.unwrap_or_else(|| occurred_at.clone());
    let state = required_string(values, "state")?;
    let repository = string_at(values, "repository.full_name").unwrap_or_default();
    let mut payload = Map::from_iter([
        ("number".to_owned(), Value::from(number)),
        ("repository".to_owned(), Value::from(repository.clone())),
        ("state".to_owned(), Value::from(state.clone())),
        (
            "push_protection_bypassed".to_owned(),
            Value::from(bool_at(values, "push_protection_bypassed")),
        ),
        ("created_at".to_owned(), Value::from(created_at)),
        ("updated_at".to_owned(), Value::from(occurred_at.clone())),
    ]);
    let strings = [
        ("secret_type", "secret_type"),
        ("secret_type_display_name", "secret_type_display_name"),
        ("resolution", "resolution"),
        ("resolution_comment", "resolution_comment"),
        ("resolved_by", "resolved_by.login"),
        (
            "push_protection_bypassed_by",
            "push_protection_bypassed_by.login",
        ),
        ("url", "url"),
        ("html_url", "html_url"),
    ];
    for (target, source) in strings {
        insert_optional(&mut payload, target, string_at(values, source));
    }
    for (target, source) in [
        ("resolved_by_id", "resolved_by.id"),
        (
            "push_protection_bypassed_by_id",
            "push_protection_bypassed_by.id",
        ),
    ] {
        if let Some(id) = value_at(values, source)
            .and_then(Value::as_i64)
            .filter(|v| *v > 0)
        {
            payload.insert(target.to_owned(), Value::from(id));
        }
    }
    for field in ["resolved_at", "push_protection_bypassed_at"] {
        insert_optional(&mut payload, field, timestamp_optional(values, field)?);
    }
    let mut attributes = BTreeMap::from([
        ("alert_number".to_owned(), number.to_string()),
        ("family".to_owned(), "secret_scanning_alert".to_owned()),
        ("owner".to_owned(), kernel.owner.clone()),
        ("state".to_owned(), state),
        (
            "push_protection_bypassed".to_owned(),
            bool_at(values, "push_protection_bypassed").to_string(),
        ),
    ]);
    if !repository.is_empty() {
        attributes.insert("repository".to_owned(), repository.clone());
    }
    for (target, source) in [
        ("html_url", "html_url"),
        ("resolution", "resolution"),
        ("resolved_by", "resolved_by.login"),
        ("resolved_by_id", "resolved_by.id"),
        ("secret_type", "secret_type"),
        ("secret_type_display_name", "secret_type_display_name"),
        (
            "push_protection_bypassed_by",
            "push_protection_bypassed_by.login",
        ),
        (
            "push_protection_bypassed_by_id",
            "push_protection_bypassed_by.id",
        ),
    ] {
        if let Some(value) = scalar_at(values, source) {
            attributes.insert(target.to_owned(), value);
        }
    }
    let identity_scope = if repository.is_empty() {
        kernel.owner.clone()
    } else {
        repository
    };
    Ok((
        "github.secret_scanning_alert",
        "github/secret_scanning_alert/v1",
        format!("{identity_scope}:{number}"),
        occurred_at,
        attributes,
        Value::Object(payload),
    ))
}
