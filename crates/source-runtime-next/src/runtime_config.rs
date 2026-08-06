use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use crate::aws_secret_store::parse_aws_secret_reference;

const MAX_CONFIG_ENTRIES: usize = 256;
const MAX_CONFIG_KEY_BYTES: usize = 128;
const MAX_CONFIG_VALUE_BYTES: usize = 64 * 1024;
const ENV_PREFIX: &str = "env:";
/// Store-native reference prefixes that the compatibility runtime recognizes
/// (`parseOpaqueReference`) but does not resolve natively. They have no Rust
/// backend resolver and must be projected into `env:` references by deployment
/// automation, matching the Go credential-store contract.
const OPAQUE_REFERENCE_PREFIXES: [&str; 4] = ["gsm:", "azkv:", "vault:", "infisical:"];
const CREDENTIAL_PREFIX: &str = "credential:";
const AWS_SECRET_PREFIX: &str = "aws-sm:";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeConfigError {
    TooManyEntries,
    InvalidKey,
    ValueTooLong(String),
    EmptyEnvironmentReference(String),
    DisallowedEnvironmentReference { key: String, name: String },
    MissingEnvironmentReference { key: String, name: String },
    EmptySensitiveEnvironmentValue(String),
    InvalidCredentialReference(String),
    InvalidAwsSecretReference(String),
    NativeReferenceRequiresEnvProjection { key: String, prefix: &'static str },
    InvalidOpaqueReference { key: String, prefix: &'static str },
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
            Self::InvalidCredentialReference(key) => write!(
                formatter,
                "stored source runtime config {key:?} has an invalid credential reference"
            ),
            Self::InvalidAwsSecretReference(key) => write!(
                formatter,
                "stored source runtime config {key:?} has an invalid aws-sm reference"
            ),
            Self::NativeReferenceRequiresEnvProjection { key, prefix } => write!(
                formatter,
                "stored source runtime config {key:?} uses a native {prefix} reference with no Rust resolver; project it into an env: reference"
            ),
            Self::InvalidOpaqueReference { key, prefix } => write!(
                formatter,
                "stored source runtime config {key:?} has an invalid {prefix} reference"
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
/// Other secret-store reference kinds (`gsm:`, `azkv:`, `vault:`, `infisical:`)
/// are recognized as native opaque references but have no Rust backend resolver;
/// they fail closed with an env-projection requirement so callers cannot
/// silently hand them to another runtime.
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
        if trimmed.starts_with(CREDENTIAL_PREFIX) {
            if parse_credential_reference(trimmed).is_none() {
                return Err(RuntimeConfigError::InvalidCredentialReference(key.clone()));
            }
            resolved.insert(key.clone(), value.clone());
            continue;
        }
        if trimmed.starts_with(AWS_SECRET_PREFIX) {
            if parse_aws_secret_reference(trimmed).is_err() {
                return Err(RuntimeConfigError::InvalidAwsSecretReference(key.clone()));
            }
            resolved.insert(key.clone(), value.clone());
            continue;
        }
        if let Some((prefix, secret_id, _field)) = parse_opaque_reference(trimmed) {
            if secret_id.is_empty() {
                return Err(RuntimeConfigError::InvalidOpaqueReference {
                    key: key.clone(),
                    prefix,
                });
            }
            return Err(RuntimeConfigError::NativeReferenceRequiresEnvProjection {
                key: key.clone(),
                prefix,
            });
        }
        resolved.insert(key.clone(), value.clone());
    }
    Ok(resolved)
}

/// Return whether a stored runtime config contains an exact connector-vault
/// reference that still needs durable resolution.
pub fn contains_credential_references(values: &BTreeMap<String, String>) -> bool {
    values
        .values()
        .any(|value| parse_credential_reference(value).is_some())
}

/// Parse the closed `credential:<id>:<field>` reference shape shared with the
/// compatibility runtime. IDs and fields are bounded to safe reference
/// components before they may reach storage.
pub fn parse_credential_reference(value: &str) -> Option<(&str, &str)> {
    let value = value.trim();
    let rest = value.strip_prefix(CREDENTIAL_PREFIX)?;
    let (id, field) = rest.split_once(':')?;
    let id = id.trim();
    let field = field.trim();
    if field.contains(':') || !valid_reference_part(id) || !valid_reference_part(field) {
        return None;
    }
    Some((id, field))
}

/// Parse a store-native opaque reference (`gsm:`, `azkv:`, `vault:`,
/// `infisical:`) the same way the compatibility runtime's `parseOpaqueReference`
/// does: split the body into a secret id and an optional `#field`. These stores
/// have no native Rust resolver; the caller must project them into `env:`
/// references. The secret id is not character-validated here, matching the Go
/// opaque parser, and is already bounded by the per-value length check. Returns
/// `None` for values that are not one of the recognized opaque native prefixes.
fn parse_opaque_reference(value: &str) -> Option<(&'static str, &str, Option<&str>)> {
    let trimmed = value.trim();
    let mut matched: Option<&'static str> = None;
    for candidate in OPAQUE_REFERENCE_PREFIXES {
        if trimmed.starts_with(candidate) {
            matched = Some(candidate);
            break;
        }
    }
    let prefix = matched?;
    let body = trimmed[prefix.len()..].trim();
    let (secret_id, field) = match body.split_once('#') {
        Some((secret_id, field)) => (secret_id.trim(), Some(field.trim())),
        None => (body, None),
    };
    Some((prefix, secret_id, field))
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

fn valid_reference_part(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONFIG_KEY_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
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
    fn disallowed_and_native_references_fail_without_exposing_values() {
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

        let credential = resolve_environment_references(
            "github",
            &BTreeMap::from([(
                "token".to_owned(),
                "credential:credential-id:token".to_owned(),
            )]),
            &BTreeSet::new(),
            |_| None,
        )
        .unwrap();
        assert_eq!(
            credential.get("token").map(String::as_str),
            Some("credential:credential-id:token")
        );

        // A well-formed native gsm: reference is recognized as a known opaque
        // reference kind but has no Rust resolver; it fails closed with an
        // env-projection requirement and never echoes the secret address.
        let native = resolve_environment_references(
            "github",
            &BTreeMap::from([("token".to_owned(), "gsm:project/secret#token".to_owned())]),
            &BTreeSet::new(),
            |_| None,
        )
        .unwrap_err();
        assert!(matches!(
            native,
            RuntimeConfigError::NativeReferenceRequiresEnvProjection { prefix: "gsm:", .. }
        ));
        assert!(!native.to_string().contains("project/secret#token"));
    }

    #[test]
    fn opaque_native_references_require_env_projection_without_exposing_values() {
        for (prefix, reference) in [
            ("gsm:", "gsm:projects/p/secrets/s/versions/latest#token"),
            (
                "azkv:",
                "azkv:https://vault.vault.azure.net/secrets/token/value",
            ),
            ("vault:", "vault:secret/data/github#token"),
            (
                "infisical:",
                "infisical://app.env.dev/PROJECT_NAME/github/TOKEN",
            ),
        ] {
            let error = resolve_environment_references(
                "github",
                &BTreeMap::from([("token".to_owned(), reference.to_owned())]),
                &BTreeSet::new(),
                |_| None,
            )
            .unwrap_err();
            assert!(
                matches!(
                    error,
                    RuntimeConfigError::NativeReferenceRequiresEnvProjection { prefix: p, .. } if p == prefix
                ),
                "{reference} should require env projection"
            );
            // The secret address and field must never appear in operator output.
            assert!(!error.to_string().contains(reference));
            let without_field = reference
                .split_once('#')
                .map_or(reference, |(left, _)| left);
            assert!(!error.to_string().contains(without_field));
        }
    }

    #[test]
    fn malformed_opaque_native_references_fail_with_distinct_error() {
        for (prefix, reference) in [
            ("gsm:", "gsm:"),
            ("gsm:", "gsm:#token"),
            ("azkv:", " azkv: "),
            ("vault:", "vault:#password"),
            ("infisical:", "infisical:"),
        ] {
            let error = resolve_environment_references(
                "github",
                &BTreeMap::from([("api_key".to_owned(), reference.to_owned())]),
                &BTreeSet::new(),
                |_| None,
            )
            .unwrap_err();
            assert!(
                matches!(
                    error,
                    RuntimeConfigError::InvalidOpaqueReference { prefix: p, .. } if p == prefix
                ),
                "{reference:?} should be an invalid opaque reference"
            );
            // A non-empty field after `#` is the only potentially sensitive
            // fragment in a malformed reference; it must not appear in operator
            // output. The prefix itself is not secret and is intentionally
            // reported alongside the config key.
            if let Some((_, field)) = reference.trim().split_once('#') {
                let field = field.trim();
                if !field.is_empty() {
                    assert!(
                        !error.to_string().contains(field),
                        "field {field:?} leaked from {reference:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn credential_references_are_exact_and_bounded() {
        let values = BTreeMap::from([(
            "token".to_owned(),
            " credential:credential-id:token ".to_owned(),
        )]);
        assert!(contains_credential_references(&values));
        assert_eq!(
            parse_credential_reference(values.get("token").unwrap()),
            Some(("credential-id", "token"))
        );
        for invalid in [
            "credential::token",
            "credential:id:",
            "credential:id:token:extra",
            "credential:id/other:token",
            "credential:id:token/value",
        ] {
            assert_eq!(parse_credential_reference(invalid), None);
            let error = resolve_environment_references(
                "github",
                &BTreeMap::from([("token".to_owned(), invalid.to_owned())]),
                &BTreeSet::new(),
                |_| None,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                RuntimeConfigError::InvalidCredentialReference(_)
            ));
        }
    }

    #[test]
    fn aws_secret_references_are_preserved_only_when_well_formed() {
        let reference = "aws-sm:us-east-1:cerebro/tenant-a/github/runtime-a/credentials#token";
        let values = BTreeMap::from([("token".to_owned(), reference.to_owned())]);
        let resolved =
            resolve_environment_references("github", &values, &BTreeSet::new(), |_| None).unwrap();
        assert_eq!(resolved, values);

        for invalid in [
            "aws-sm:",
            "aws-sm:us-east-1:",
            "aws-sm:us-east-1:secret#",
            "aws-sm:us-east-1:secret#field/other",
        ] {
            let error = resolve_environment_references(
                "github",
                &BTreeMap::from([("token".to_owned(), invalid.to_owned())]),
                &BTreeSet::new(),
                |_| None,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                RuntimeConfigError::InvalidAwsSecretReference(_)
            ));
            assert!(!error.to_string().contains(invalid));
        }
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
