use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

const MAX_CONFIG_ENTRIES: usize = 256;
const MAX_CONFIG_KEY_BYTES: usize = 128;
const MAX_CONFIG_VALUE_BYTES: usize = 64 * 1024;
const ENV_PREFIX: &str = "env:";
const UNSUPPORTED_REFERENCE_PREFIXES: [&str; 6] = [
    "credential:",
    "aws-sm:",
    "gsm:",
    "azkv:",
    "vault:",
    "infisical:",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeConfigError {
    TooManyEntries,
    InvalidKey,
    ValueTooLong(String),
    EmptyEnvironmentReference(String),
    DisallowedEnvironmentReference { key: String, name: String },
    MissingEnvironmentReference { key: String, name: String },
    EmptySensitiveEnvironmentValue(String),
    UnsupportedReference { key: String, prefix: &'static str },
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries => {
                formatter.write_str("stored source runtime config has too many entries")
            }
            Self::InvalidKey => formatter.write_str("stored source runtime config key is invalid"),
            Self::ValueTooLong(key) => {
                write!(
                    formatter,
                    "stored source runtime config {key:?} is too large"
                )
            }
            Self::EmptyEnvironmentReference(key) => write!(
                formatter,
                "stored source runtime config {key:?} has an empty environment reference"
            ),
            Self::DisallowedEnvironmentReference { key, name } => write!(
                formatter,
                "stored source runtime config {key:?} references disallowed environment variable {name:?}"
            ),
            Self::MissingEnvironmentReference { key, name } => write!(
                formatter,
                "stored source runtime config {key:?} references unset environment variable {name:?}"
            ),
            Self::EmptySensitiveEnvironmentValue(key) => write!(
                formatter,
                "stored source runtime config {key:?} resolved to an empty sensitive value"
            ),
            Self::UnsupportedReference { key, prefix } => write!(
                formatter,
                "stored source runtime config {key:?} uses unsupported {prefix} reference"
            ),
        }
    }
}

impl Error for RuntimeConfigError {}

/// Resolve bounded `env:` references from one stored source runtime.
///
/// Only the canonical `CEREBRO_SOURCE_<SOURCE>_<KEY>` name or an explicitly
/// allowlisted name may be read. Query-like values such as `phrase=env:prod`
/// remain literal unless their environment name is explicitly authorized.
/// Other secret-store reference kinds fail closed until their Rust resolver is
/// configured; callers cannot silently hand them to another runtime.
pub fn resolve_environment_references(
    source_id: &str,
    values: &BTreeMap<String, String>,
    explicit_allowlist: &BTreeSet<String>,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<BTreeMap<String, String>, RuntimeConfigError> {
    if values.len() > MAX_CONFIG_ENTRIES {
        return Err(RuntimeConfigError::TooManyEntries);
    }
    let mut resolved = BTreeMap::new();
    for (key, value) in values {
        validate_entry(key, value)?;
        let trimmed = value.trim();
        if let Some(name) = trimmed.strip_prefix(ENV_PREFIX) {
            let name = name.trim();
            if name.is_empty() {
                return Err(RuntimeConfigError::EmptyEnvironmentReference(key.clone()));
            }
            let canonical = canonical_environment_name(source_id, key);
            let explicitly_allowed = explicit_allowlist.contains(name);
            if literal_env_prefix_key(key) && name != canonical && !explicitly_allowed {
                resolved.insert(key.clone(), value.clone());
                continue;
            }
            if name != canonical && !explicitly_allowed {
                return Err(RuntimeConfigError::DisallowedEnvironmentReference {
                    key: key.clone(),
                    name: name.to_owned(),
                });
            }
            let secret =
                lookup(name).ok_or_else(|| RuntimeConfigError::MissingEnvironmentReference {
                    key: key.clone(),
                    name: name.to_owned(),
                })?;
            if sensitive_key(key) && secret.trim().is_empty() {
                return Err(RuntimeConfigError::EmptySensitiveEnvironmentValue(
                    key.clone(),
                ));
            }
            if secret.len() > MAX_CONFIG_VALUE_BYTES {
                return Err(RuntimeConfigError::ValueTooLong(key.clone()));
            }
            resolved.insert(key.clone(), secret);
            continue;
        }
        if let Some(prefix) = UNSUPPORTED_REFERENCE_PREFIXES
            .into_iter()
            .find(|prefix| trimmed.starts_with(prefix))
        {
            return Err(RuntimeConfigError::UnsupportedReference {
                key: key.clone(),
                prefix,
            });
        }
        resolved.insert(key.clone(), value.clone());
    }
    Ok(resolved)
}

fn validate_entry(key: &str, value: &str) -> Result<(), RuntimeConfigError> {
    if key.is_empty()
        || key.trim() != key
        || key.len() > MAX_CONFIG_KEY_BYTES
        || key.chars().any(char::is_control)
    {
        return Err(RuntimeConfigError::InvalidKey);
    }
    if value.len() > MAX_CONFIG_VALUE_BYTES {
        return Err(RuntimeConfigError::ValueTooLong(key.to_owned()));
    }
    Ok(())
}

fn canonical_environment_name(source_id: &str, key: &str) -> String {
    format!(
        "CEREBRO_SOURCE_{}_{}",
        environment_component(source_id),
        environment_component(key)
    )
}

fn environment_component(value: &str) -> String {
    let component = value
        .trim()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let component = component.trim_matches('_');
    if component.is_empty() {
        "CONFIG".to_owned()
    } else {
        component.to_owned()
    }
}

fn literal_env_prefix_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "filter" | "phrase" | "q" | "search"
    )
}

fn sensitive_key(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase();
    ["credential", "password", "private_key", "secret", "token"]
        .into_iter()
        .any(|part| normalized.contains(part))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_and_explicit_environment_references_resolve() {
        let values = BTreeMap::from([
            (
                "token".to_owned(),
                "env:CEREBRO_SOURCE_GITHUB_TOKEN".to_owned(),
            ),
            ("organization".to_owned(), "env:SHARED_ORG".to_owned()),
        ]);
        let allowlist = BTreeSet::from(["SHARED_ORG".to_owned()]);
        let resolved =
            resolve_environment_references("github", &values, &allowlist, |name| match name {
                "CEREBRO_SOURCE_GITHUB_TOKEN" => Some("secret-value".to_owned()),
                "SHARED_ORG" => Some("engineering".to_owned()),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            resolved.get("token").map(String::as_str),
            Some("secret-value")
        );
        assert_eq!(
            resolved.get("organization").map(String::as_str),
            Some("engineering")
        );
    }

    #[test]
    fn disallowed_and_unsupported_references_fail_without_exposing_values() {
        let disallowed = resolve_environment_references(
            "github",
            &BTreeMap::from([("token".to_owned(), "env:OTHER_TOKEN".to_owned())]),
            &BTreeSet::new(),
            |_| Some("must-not-appear".to_owned()),
        )
        .unwrap_err();
        assert!(matches!(
            disallowed,
            RuntimeConfigError::DisallowedEnvironmentReference { .. }
        ));
        assert!(!disallowed.to_string().contains("must-not-appear"));

        let unsupported = resolve_environment_references(
            "github",
            &BTreeMap::from([(
                "token".to_owned(),
                "credential:credential-id:token".to_owned(),
            )]),
            &BTreeSet::new(),
            |_| None,
        )
        .unwrap_err();
        assert!(matches!(
            unsupported,
            RuntimeConfigError::UnsupportedReference {
                prefix: "credential:",
                ..
            }
        ));
        assert!(!unsupported.to_string().contains("credential-id"));
    }

    #[test]
    fn literal_query_value_is_preserved_unless_explicitly_allowed() {
        let values = BTreeMap::from([("phrase".to_owned(), "env:prod".to_owned())]);
        let literal =
            resolve_environment_references("github", &values, &BTreeSet::new(), |_| None).unwrap();
        assert_eq!(literal, values);

        let resolved = resolve_environment_references(
            "github",
            &values,
            &BTreeSet::from(["prod".to_owned()]),
            |_| Some("production".to_owned()),
        )
        .unwrap();
        assert_eq!(
            resolved.get("phrase").map(String::as_str),
            Some("production")
        );
    }
}
