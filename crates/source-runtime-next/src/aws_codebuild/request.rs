//! Credential-free CodeBuild request planning, fanout, and response dispatch.

use std::{collections::BTreeSet, net::IpAddr};

use reqwest::{StatusCode, Url};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{
    normalize::{build_project_record, build_source_credential_record},
    wire::{
        AwsCodeBuildBatch, AwsCodeBuildError, AwsCodeBuildFamily, AwsCodeBuildRequest,
        AwsCodeBuildRequestKind,
    },
};

pub(super) const MAX_CURSOR_BYTES: usize = 4_096;
const MAX_PROVIDER_RECORDS: usize = 1_000;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const PROJECT_BATCH_SIZE: usize = 100;

/// Provider-local CodeBuild request and response state machine.
#[derive(Clone, Debug)]
pub struct AwsCodeBuildKernel {
    base_url: Url,
    account_id: String,
    region: String,
    fingerprint: [u8; 32],
}

impl AwsCodeBuildKernel {
    /// Build a kernel for one AWS account, region, and CodeBuild origin.
    pub fn new(base_url: &str, account_id: &str, region: &str) -> Result<Self, AwsCodeBuildError> {
        let base_url = validate_origin(base_url)?;
        let account_id = account_id.trim();
        if account_id.len() != 12 || !account_id.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AwsCodeBuildError::InvalidAccountId);
        }
        let region = region.trim();
        if region.is_empty()
            || region.len() > 63
            || !region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(AwsCodeBuildError::InvalidRegion);
        }
        let fingerprint = kernel_fingerprint(base_url.as_str(), account_id, region);
        Ok(Self {
            base_url,
            account_id: account_id.to_owned(),
            region: region.to_owned(),
            fingerprint,
        })
    }

    /// Plan the first or next request for one CodeBuild family.
    pub fn plan(
        &self,
        family: AwsCodeBuildFamily,
        cursor: Option<&str>,
    ) -> Result<AwsCodeBuildRequest, AwsCodeBuildError> {
        let (kind, cursor) = match family {
            AwsCodeBuildFamily::Project => (
                AwsCodeBuildRequestKind::ListProjects,
                cursor.map(validate_cursor).transpose()?.map(str::to_owned),
            ),
            AwsCodeBuildFamily::SourceCredential => {
                if cursor.is_some() {
                    return Err(AwsCodeBuildError::CursorNotSupported);
                }
                (AwsCodeBuildRequestKind::ListSourceCredentials, None)
            }
        };
        self.request(family, kind, cursor, None)
    }

    /// Decode one response for a request issued by this exact kernel.
    ///
    /// `provider_error_code` must contain only the safe Smithy error identifier,
    /// never a provider message or body.
    pub fn decode(
        &self,
        request: &AwsCodeBuildRequest,
        status: StatusCode,
        provider_error_code: Option<&str>,
        body: &[u8],
    ) -> Result<AwsCodeBuildBatch, AwsCodeBuildError> {
        self.validate_request(request)?;
        if !status.is_success() {
            return Err(AwsCodeBuildError::ProviderFailure {
                status: status.as_u16(),
                code: safe_error_code(provider_error_code),
            });
        }
        let response = decode_json(body)?;
        match request.kind {
            AwsCodeBuildRequestKind::ListProjects => self.decode_project_list(request, &response),
            AwsCodeBuildRequestKind::BatchGetProjects => self.decode_project_batch(&response),
            AwsCodeBuildRequestKind::ListSourceCredentials => {
                self.decode_source_credentials(&response)
            }
        }
    }

    fn decode_project_list(
        &self,
        request: &AwsCodeBuildRequest,
        response: &Value,
    ) -> Result<AwsCodeBuildBatch, AwsCodeBuildError> {
        let object = value_object(response)?;
        let names = clean_string_array(object, "projects")?;
        bounded_records(names.len())?;
        let mut requests = Vec::with_capacity(names.len().div_ceil(PROJECT_BATCH_SIZE));
        for batch in names.chunks(PROJECT_BATCH_SIZE) {
            requests.push(self.request(
                request.family,
                AwsCodeBuildRequestKind::BatchGetProjects,
                None,
                Some(batch.to_vec()),
            )?);
        }
        Ok(AwsCodeBuildBatch {
            records: Vec::new(),
            requests,
            next_cursor: response_cursor(object)?,
        })
    }

    fn decode_project_batch(
        &self,
        response: &Value,
    ) -> Result<AwsCodeBuildBatch, AwsCodeBuildError> {
        let object = value_object(response)?;
        let projects = optional_array(object, "projects")?;
        bounded_records(projects.len())?;
        let records = projects
            .iter()
            .map(|project| {
                build_project_record(&self.account_id, &self.region, value_object(project)?)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AwsCodeBuildBatch {
            records,
            requests: Vec::new(),
            next_cursor: None,
        })
    }

    fn decode_source_credentials(
        &self,
        response: &Value,
    ) -> Result<AwsCodeBuildBatch, AwsCodeBuildError> {
        let object = value_object(response)?;
        let credentials = optional_array(object, "sourceCredentialsInfos")?;
        bounded_records(credentials.len())?;
        let mut records = credentials
            .iter()
            .map(|credential| {
                build_source_credential_record(
                    &self.account_id,
                    &self.region,
                    value_object(credential)?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        records.sort_by(|left, right| left.fields["resource_id"].cmp(&right.fields["resource_id"]));
        Ok(AwsCodeBuildBatch {
            records,
            requests: Vec::new(),
            next_cursor: None,
        })
    }

    fn request(
        &self,
        family: AwsCodeBuildFamily,
        kind: AwsCodeBuildRequestKind,
        cursor: Option<String>,
        names: Option<Vec<String>>,
    ) -> Result<AwsCodeBuildRequest, AwsCodeBuildError> {
        validate_kind_family(kind, family)?;
        let body = request_body(kind, cursor.as_deref(), names.as_deref())?;
        Ok(AwsCodeBuildRequest {
            url: self.base_url.clone(),
            family,
            kind,
            account_id: self.account_id.clone(),
            region: self.region.clone(),
            cursor,
            names,
            body,
            kernel_fingerprint: self.fingerprint,
        })
    }

    fn validate_request(&self, request: &AwsCodeBuildRequest) -> Result<(), AwsCodeBuildError> {
        validate_kind_family(request.kind, request.family)?;
        if request.url != self.base_url
            || request.account_id != self.account_id
            || request.region != self.region
            || request.kernel_fingerprint != self.fingerprint
        {
            return Err(AwsCodeBuildError::RequestScopeMismatch);
        }
        let expected = request_body(
            request.kind,
            request.cursor.as_deref(),
            request.names.as_deref(),
        )?;
        if request.body != expected {
            return Err(AwsCodeBuildError::RequestScopeMismatch);
        }
        Ok(())
    }
}

fn validate_origin(value: &str) -> Result<Url, AwsCodeBuildError> {
    let url = Url::parse(value).map_err(|_| AwsCodeBuildError::InvalidBaseUrl)?;
    let host = url.host_str().ok_or(AwsCodeBuildError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".local")
        || host.parse::<IpAddr>().is_ok()
    {
        return Err(AwsCodeBuildError::InvalidBaseUrl);
    }
    Ok(url)
}

fn kernel_fingerprint(origin: &str, account_id: &str, region: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    for value in [origin, account_id, region] {
        digest.update(value.len().to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.finalize().into()
}

fn validate_kind_family(
    kind: AwsCodeBuildRequestKind,
    family: AwsCodeBuildFamily,
) -> Result<(), AwsCodeBuildError> {
    let matches = match family {
        AwsCodeBuildFamily::Project => matches!(
            kind,
            AwsCodeBuildRequestKind::ListProjects | AwsCodeBuildRequestKind::BatchGetProjects
        ),
        AwsCodeBuildFamily::SourceCredential => {
            kind == AwsCodeBuildRequestKind::ListSourceCredentials
        }
    };
    if matches {
        Ok(())
    } else {
        Err(AwsCodeBuildError::RequestScopeMismatch)
    }
}

fn request_body(
    kind: AwsCodeBuildRequestKind,
    cursor: Option<&str>,
    names: Option<&[String]>,
) -> Result<Vec<u8>, AwsCodeBuildError> {
    let body = match kind {
        AwsCodeBuildRequestKind::ListProjects => {
            if names.is_some() {
                return Err(AwsCodeBuildError::RequestScopeMismatch);
            }
            let mut object = Map::new();
            if let Some(cursor) = cursor {
                object.insert("nextToken".to_owned(), json!(validate_cursor(cursor)?));
            }
            Value::Object(object)
        }
        AwsCodeBuildRequestKind::BatchGetProjects => {
            if cursor.is_some() {
                return Err(AwsCodeBuildError::RequestScopeMismatch);
            }
            let names = names.ok_or(AwsCodeBuildError::RequestScopeMismatch)?;
            if names.is_empty() || names.len() > PROJECT_BATCH_SIZE {
                return Err(AwsCodeBuildError::RequestScopeMismatch);
            }
            let mut seen = BTreeSet::new();
            for name in names {
                if name.is_empty()
                    || name.trim() != name
                    || name.len() > 255
                    || name.chars().any(char::is_control)
                    || !seen.insert(name)
                {
                    return Err(AwsCodeBuildError::RequestScopeMismatch);
                }
            }
            json!({"names": names})
        }
        AwsCodeBuildRequestKind::ListSourceCredentials => {
            if cursor.is_some() || names.is_some() {
                return Err(AwsCodeBuildError::RequestScopeMismatch);
            }
            json!({})
        }
    };
    serde_json::to_vec(&body).map_err(|_| AwsCodeBuildError::RequestScopeMismatch)
}

fn decode_json(body: &[u8]) -> Result<Value, AwsCodeBuildError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(AwsCodeBuildError::InvalidResponse);
    }
    serde_json::from_slice(body).map_err(|_| AwsCodeBuildError::InvalidResponse)
}

pub(super) fn value_object(value: &Value) -> Result<&Map<String, Value>, AwsCodeBuildError> {
    value.as_object().ok_or(AwsCodeBuildError::InvalidResponse)
}

pub(super) fn optional_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, AwsCodeBuildError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(_) => Err(AwsCodeBuildError::InvalidResponse),
    }
}

pub(super) fn optional_array<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a [Value], AwsCodeBuildError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(values)) => Ok(values),
        Some(_) => Err(AwsCodeBuildError::InvalidResponse),
    }
}

pub(super) fn response_string_member<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, AwsCodeBuildError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.trim()).filter(|value| !value.is_empty())),
        Some(_) => Err(AwsCodeBuildError::InvalidResponse),
    }
}

pub(super) fn bool_member(
    object: &Map<String, Value>,
    key: &str,
) -> Result<bool, AwsCodeBuildError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(AwsCodeBuildError::InvalidResponse),
    }
}

pub(super) fn integer_string(
    object: &Map<String, Value>,
    key: &str,
) -> Result<String, AwsCodeBuildError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::Number(value)) if value.is_i64() || value.is_u64() => Ok(value.to_string()),
        Some(_) => Err(AwsCodeBuildError::InvalidResponse),
    }
}

pub(super) fn validate_optional_number(
    object: &Map<String, Value>,
    key: &str,
) -> Result<(), AwsCodeBuildError> {
    match object.get(key) {
        None | Some(Value::Null) | Some(Value::Number(_)) => Ok(()),
        Some(_) => Err(AwsCodeBuildError::InvalidResponse),
    }
}

fn clean_string_array(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Vec<String>, AwsCodeBuildError> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for value in optional_array(object, key)? {
        let value = value
            .as_str()
            .ok_or(AwsCodeBuildError::InvalidResponse)?
            .trim();
        if !value.is_empty() && seen.insert(value.to_owned()) {
            result.push(value.to_owned());
        }
    }
    Ok(result)
}

fn response_cursor(object: &Map<String, Value>) -> Result<Option<String>, AwsCodeBuildError> {
    match object.get("nextToken") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(validate_cursor(value)?.to_owned())),
        Some(_) => Err(AwsCodeBuildError::InvalidResponse),
    }
}

fn validate_cursor(value: &str) -> Result<&str, AwsCodeBuildError> {
    if value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(AwsCodeBuildError::InvalidCursor)
    } else {
        Ok(value)
    }
}

pub(super) fn bounded_records(count: usize) -> Result<(), AwsCodeBuildError> {
    if count > MAX_PROVIDER_RECORDS {
        Err(AwsCodeBuildError::InvalidResponse)
    } else {
        Ok(())
    }
}

fn safe_error_code(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        let value = value.split(':').next().unwrap_or_default().trim();
        (!value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
        .then(|| value.to_owned())
    })
}
