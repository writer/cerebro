use std::collections::{BTreeMap, btree_map::Entry};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

const AWS_SECRET_PREFIX: &str = "aws-sm:";
const MAX_SECRET_ID_BYTES: usize = 2_048;
const MAX_FIELD_BYTES: usize = 128;
const MAX_SECRET_VALUE_BYTES: usize = 256 * 1_024;

pub struct AwsSecretReference {
    region: Option<String>,
    secret_id: String,
    field: Option<String>,
}

impl AwsSecretReference {
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    pub fn secret_id(&self) -> &str {
        &self.secret_id
    }

    pub fn field(&self) -> Option<&str> {
        self.field.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsSecretResolutionError {
    InvalidReference(String),
    InvalidRuntimeScope,
    ReferenceOutsideRuntime(String),
    BackendUnavailable(String),
    InvalidSecretValue(String),
    MissingSecretField(String),
}

impl std::fmt::Display for AwsSecretResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidReference(key) => {
                write!(
                    formatter,
                    "source config {key:?} has an invalid aws-sm reference"
                )
            }
            Self::InvalidRuntimeScope => {
                formatter.write_str("source runtime cannot authorize AWS secret references")
            }
            Self::ReferenceOutsideRuntime(key) => write!(
                formatter,
                "source config {key:?} references an AWS secret outside this runtime"
            ),
            Self::BackendUnavailable(key) => write!(
                formatter,
                "AWS Secrets Manager could not resolve source config {key:?}"
            ),
            Self::InvalidSecretValue(key) => write!(
                formatter,
                "AWS Secrets Manager returned an invalid value for source config {key:?}"
            ),
            Self::MissingSecretField(key) => write!(
                formatter,
                "AWS Secrets Manager did not return the requested field for source config {key:?}"
            ),
        }
    }
}

impl std::error::Error for AwsSecretResolutionError {}

/// A secret value returned by the backend. This type deliberately does not
/// implement `Debug` or `Clone`, and clears its owned bytes when dropped.
pub enum AwsSecretValue {
    String(String),
    Binary(Vec<u8>),
}

impl Drop for AwsSecretValue {
    fn drop(&mut self) {
        match self {
            Self::String(value) => value.zeroize(),
            Self::Binary(value) => value.zeroize(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AwsSecretReadError;

#[async_trait]
pub trait AwsSecretReader: Send + Sync {
    async fn read_secret(
        &self,
        region: Option<&str>,
        secret_id: &str,
    ) -> Result<AwsSecretValue, AwsSecretReadError>;
}

pub fn contains_aws_secret_references(values: &BTreeMap<String, String>) -> bool {
    values
        .values()
        .any(|value| value.trim().starts_with(AWS_SECRET_PREFIX))
}

pub fn parse_aws_secret_reference(
    value: &str,
) -> Result<Option<AwsSecretReference>, AwsSecretResolutionError> {
    let value = value.trim();
    let Some(body) = value.strip_prefix(AWS_SECRET_PREFIX) else {
        return Ok(None);
    };
    let (secret_id, field) = body
        .split_once('#')
        .map_or((body, None), |(secret_id, field)| (secret_id, Some(field)));
    let mut secret_id = secret_id.trim();
    let field = field.map(str::trim);
    if secret_id.is_empty()
        || secret_id.len() > MAX_SECRET_ID_BYTES
        || field.is_some_and(|field| {
            field.is_empty() || field.len() > MAX_FIELD_BYTES || !valid_reference_part(field)
        })
    {
        return Err(AwsSecretResolutionError::InvalidReference(
            "secret".to_owned(),
        ));
    }

    let region = if secret_id.starts_with("arn:") {
        Some(
            parse_secrets_manager_arn_region(secret_id)
                .ok_or_else(|| AwsSecretResolutionError::InvalidReference("secret".to_owned()))?
                .to_owned(),
        )
    } else if let Some((candidate, remainder)) = secret_id.split_once(':') {
        if valid_aws_region(candidate) {
            let remainder = remainder.trim();
            if remainder.is_empty() {
                return Err(AwsSecretResolutionError::InvalidReference(
                    "secret".to_owned(),
                ));
            }
            secret_id = remainder;
            Some(candidate.to_owned())
        } else {
            None
        }
    } else {
        None
    };
    if secret_id.is_empty() || secret_id.len() > MAX_SECRET_ID_BYTES {
        return Err(AwsSecretResolutionError::InvalidReference(
            "secret".to_owned(),
        ));
    }
    Ok(Some(AwsSecretReference {
        region,
        secret_id: secret_id.to_owned(),
        field: field.map(str::to_owned),
    }))
}

fn parse_secrets_manager_arn_region(secret_id: &str) -> Option<&str> {
    let mut parts = secret_id.splitn(7, ':');
    let arn = parts.next()?;
    let partition = parts.next()?;
    let service = parts.next()?;
    let region = parts.next()?;
    let account = parts.next()?;
    let resource_kind = parts.next()?;
    let resource = parts.next()?;
    (arn == "arn"
        && partition.starts_with("aws")
        && service == "secretsmanager"
        && valid_aws_region(region)
        && account.len() == 12
        && account.bytes().all(|byte| byte.is_ascii_digit())
        && resource_kind == "secret"
        && !resource.is_empty())
    .then_some(region)
}

pub async fn resolve_aws_secret_references<Reader>(
    tenant_id: &str,
    source_id: &str,
    runtime_id: &str,
    values: &BTreeMap<String, String>,
    reader: &Reader,
) -> Result<BTreeMap<String, String>, AwsSecretResolutionError>
where
    Reader: AwsSecretReader,
{
    let expected_secret = runtime_secret_name(tenant_id, source_id, runtime_id)
        .ok_or(AwsSecretResolutionError::InvalidRuntimeScope)?;
    let mut requests = BTreeMap::<(String, String), Vec<(String, Option<String>)>>::new();
    for (key, value) in values {
        let reference = parse_aws_secret_reference(value)
            .map_err(|_| AwsSecretResolutionError::InvalidReference(key.clone()))?;
        let Some(reference) = reference else {
            continue;
        };
        let secret_name = aws_secret_name(reference.secret_id());
        if secret_name != expected_secret
            && !secret_name.starts_with(&format!("{expected_secret}-"))
        {
            return Err(AwsSecretResolutionError::ReferenceOutsideRuntime(
                key.clone(),
            ));
        }
        let group = (
            reference.region().unwrap_or_default().to_owned(),
            reference.secret_id().to_owned(),
        );
        match requests.entry(group) {
            Entry::Vacant(entry) => {
                entry.insert(vec![(key.clone(), reference.field().map(str::to_owned))]);
            }
            Entry::Occupied(mut entry) => {
                entry
                    .get_mut()
                    .push((key.clone(), reference.field().map(str::to_owned)));
            }
        }
    }
    if requests.is_empty() {
        return Ok(values.clone());
    }

    let mut resolved = values.clone();
    for ((region, secret_id), fields) in requests {
        let secret = reader
            .read_secret((!region.is_empty()).then_some(region.as_str()), &secret_id)
            .await
            .map_err(|_| AwsSecretResolutionError::BackendUnavailable(fields[0].0.clone()))?;
        let text = secret_text(&secret);
        if text.len() > MAX_SECRET_VALUE_BYTES {
            return Err(AwsSecretResolutionError::InvalidSecretValue(
                fields[0].0.clone(),
            ));
        }
        for (key, field) in fields {
            let value = match field {
                Some(field) => extract_json_field(&text, &field, &key)?,
                None => text.to_string(),
            };
            if value.len() > MAX_SECRET_VALUE_BYTES {
                return Err(AwsSecretResolutionError::InvalidSecretValue(key));
            }
            resolved.insert(key, value);
        }
    }
    Ok(resolved)
}

fn secret_text(secret: &AwsSecretValue) -> Zeroizing<String> {
    Zeroizing::new(match secret {
        AwsSecretValue::String(value) => value.clone(),
        AwsSecretValue::Binary(value) => general_purpose::STANDARD.encode(value),
    })
}

fn extract_json_field(
    secret: &str,
    field: &str,
    config_key: &str,
) -> Result<String, AwsSecretResolutionError> {
    let mut value = serde_json::from_str::<Value>(secret)
        .map_err(|_| AwsSecretResolutionError::InvalidSecretValue(config_key.to_owned()))?;
    let result = match value.as_object().and_then(|object| object.get(field)) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(Value::Number(value)) => Ok(value.to_string()),
        Some(Value::Bool(value)) => Ok(value.to_string()),
        Some(value) => serde_json::to_string(value)
            .map_err(|_| AwsSecretResolutionError::InvalidSecretValue(config_key.to_owned())),
        None if value.is_object() => Err(AwsSecretResolutionError::MissingSecretField(
            config_key.to_owned(),
        )),
        None => Err(AwsSecretResolutionError::InvalidSecretValue(
            config_key.to_owned(),
        )),
    };
    zeroize_json_value(&mut value);
    result
}

fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        Value::Object(object) => {
            let entries = std::mem::take(object);
            for (mut key, mut value) in entries {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn runtime_secret_name(tenant_id: &str, source_id: &str, runtime_id: &str) -> Option<String> {
    let parts = [tenant_id.trim(), source_id.trim(), runtime_id.trim()];
    parts
        .iter()
        .all(|part| valid_reference_part(part))
        .then(|| format!("cerebro/{}/{}/{}/credentials", parts[0], parts[1], parts[2]))
}

fn aws_secret_name(secret_id: &str) -> &str {
    secret_id
        .rfind(":secret:")
        .map_or(secret_id.trim(), |index| {
            secret_id[index + ":secret:".len()..].trim()
        })
}

fn valid_reference_part(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_aws_region(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 6 || !bytes[0].is_ascii_lowercase() || !bytes[1].is_ascii_lowercase() {
        return false;
    }
    let mut rest = &value[2..];
    if let Some(after_gov) = rest.strip_prefix("-gov") {
        rest = after_gov;
    }
    let Some(rest) = rest.strip_prefix('-') else {
        return false;
    };
    let Some((area, number)) = rest.rsplit_once('-') else {
        return false;
    };
    !area.is_empty()
        && area
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && number.len() == 1
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct FixtureReader {
        reads: AtomicUsize,
    }

    #[async_trait]
    impl AwsSecretReader for FixtureReader {
        async fn read_secret(
            &self,
            region: Option<&str>,
            secret_id: &str,
        ) -> Result<AwsSecretValue, AwsSecretReadError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            assert_eq!(region, Some("us-east-1"));
            assert_eq!(secret_id, "cerebro/tenant-a/github/runtime-a/credentials");
            Ok(AwsSecretValue::String(
                r#"{"enabled":true,"token":"secret-token","version":2}"#.to_owned(),
            ))
        }
    }

    #[test]
    fn parser_accepts_scoped_names_and_arns() {
        let named = parse_aws_secret_reference(
            "aws-sm:us-east-1:cerebro/tenant-a/github/runtime-a/credentials#token",
        )
        .unwrap()
        .unwrap();
        assert_eq!(named.region(), Some("us-east-1"));
        assert_eq!(
            named.secret_id(),
            "cerebro/tenant-a/github/runtime-a/credentials"
        );
        assert_eq!(named.field(), Some("token"));

        let arn = parse_aws_secret_reference(
            "aws-sm:arn:aws:secretsmanager:us-west-2:123456789012:secret:cerebro/tenant-a/github/runtime-a/credentials-AbCdEf#token",
        )
        .unwrap()
        .unwrap();
        assert_eq!(arn.region(), Some("us-west-2"));
        assert!(arn.secret_id().starts_with("arn:aws:secretsmanager:"));
        assert_eq!(arn.field(), Some("token"));
    }

    #[tokio::test]
    async fn resolver_authorizes_scope_groups_reads_and_extracts_fields() {
        let reader = FixtureReader {
            reads: AtomicUsize::new(0),
        };
        let values = BTreeMap::from([
            (
                "enabled".to_owned(),
                "aws-sm:us-east-1:cerebro/tenant-a/github/runtime-a/credentials#enabled".to_owned(),
            ),
            (
                "token".to_owned(),
                "aws-sm:us-east-1:cerebro/tenant-a/github/runtime-a/credentials#token".to_owned(),
            ),
            (
                "version".to_owned(),
                "aws-sm:us-east-1:cerebro/tenant-a/github/runtime-a/credentials#version".to_owned(),
            ),
        ]);
        let resolved =
            resolve_aws_secret_references("tenant-a", "github", "runtime-a", &values, &reader)
                .await
                .unwrap();
        assert_eq!(reader.reads.load(Ordering::Relaxed), 1);
        assert_eq!(resolved.get("enabled").map(String::as_str), Some("true"));
        assert_eq!(
            resolved.get("token").map(String::as_str),
            Some("secret-token")
        );
        assert_eq!(resolved.get("version").map(String::as_str), Some("2"));
    }

    #[tokio::test]
    async fn foreign_reference_fails_before_backend_and_errors_hide_addresses() {
        let reader = FixtureReader {
            reads: AtomicUsize::new(0),
        };
        let value = "aws-sm:us-east-1:cerebro/tenant-b/github/runtime-a/credentials#secret-token";
        let error = resolve_aws_secret_references(
            "tenant-a",
            "github",
            "runtime-a",
            &BTreeMap::from([("token".to_owned(), value.to_owned())]),
            &reader,
        )
        .await
        .unwrap_err();
        assert_eq!(reader.reads.load(Ordering::Relaxed), 0);
        assert!(matches!(
            error,
            AwsSecretResolutionError::ReferenceOutsideRuntime(_)
        ));
        assert!(!error.to_string().contains("tenant-b"));
        assert!(!error.to_string().contains("secret-token"));
    }

    #[test]
    fn malformed_references_fail_closed() {
        for value in [
            "aws-sm:",
            "aws-sm:us-east-1:",
            "aws-sm:us-east-1:secret#",
            "aws-sm:us-east-1:secret#field/other",
            "aws-sm:arn:aws:ssm:us-east-1:123456789012:secret:cerebro/tenant-a/github/runtime-a/credentials#token",
            "aws-sm:arn:aws:secretsmanager:invalid:123456789012:secret:cerebro/tenant-a/github/runtime-a/credentials#token",
            "aws-sm:arn:aws:secretsmanager:us-east-1:account:secret:cerebro/tenant-a/github/runtime-a/credentials#token",
        ] {
            assert!(
                parse_aws_secret_reference(value).is_err(),
                "{value} must fail closed"
            );
        }
        assert!(valid_aws_region("us-east-1"));
        assert!(valid_aws_region("us-gov-west-1"));
        assert!(!valid_aws_region("US-east-1"));
        assert!(!valid_aws_region("us-east"));
    }
}
