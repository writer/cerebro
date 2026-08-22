//! Bounded OpenAI request planning without credential bytes.

use std::collections::BTreeMap;

use reqwest::Url;
use serde::Serialize;

use super::{
    OpenAiError, OpenAiFamily,
    family::{BASE_PATH, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES, ORIGIN, Pagination},
};

const MAX_CONFIG_VALUE_BYTES: usize = 4 << 10;
const MAX_CURSOR_BYTES: usize = 4 << 10;

/// Public, credential-free inputs for one OpenAI page request.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct OpenAiRequestInput {
    /// Values used only for declared provider path parameters.
    pub path_parameters: BTreeMap<String, String>,
    /// Values used only for declared provider query filters.
    pub query_parameters: BTreeMap<String, String>,
    /// Requested provider page size, bounded to 1 through 1,000.
    pub page_size: Option<usize>,
    /// Opaque Go-compatible provider continuation.
    pub cursor: Option<String>,
}

/// Authentication metadata consumed by the trusted host.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenAiAuthRequirement {
    /// Declared credential operation; never a credential value.
    pub operation: String,
    /// Header name to be populated by the trusted host.
    pub header: String,
    /// Authorization scheme to be applied by the trusted host.
    pub scheme: String,
}

/// One bounded, origin-restricted OpenAI HTTP request description.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenAiRequest {
    /// Exact source family.
    pub family: String,
    /// Always `GET` for this provider slice.
    pub method: String,
    /// Fully rendered provider URL with public parameters only.
    pub url: String,
    /// Accepted response media type.
    pub accept: String,
    /// Maximum response bytes the host may return to the kernel.
    pub max_response_bytes: usize,
    /// Redirects are always disabled.
    pub allow_redirects: bool,
    /// External authentication operation metadata.
    pub auth: OpenAiAuthRequirement,
}

/// Credential-free OpenAI organization-governance planning and decode kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiKernel {
    family: OpenAiFamily,
    tenant_id: String,
}

impl OpenAiKernel {
    /// Bind a trusted tenant to one exact OpenAI family.
    pub fn new(family: OpenAiFamily, tenant_id: impl Into<String>) -> Result<Self, OpenAiError> {
        let tenant_id = tenant_id.into();
        if tenant_id.is_empty()
            || tenant_id.trim() != tenant_id
            || tenant_id.len() > 256
            || tenant_id.chars().any(char::is_control)
        {
            return Err(OpenAiError::InvalidTenant);
        }
        Ok(Self { family, tenant_id })
    }

    /// Return whether the kernel accepts credential material.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Return the trusted tenant identity.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Return the exact provider family.
    pub fn family(&self) -> OpenAiFamily {
        self.family
    }

    /// Compile public inputs into a bounded, origin-locked GET request.
    pub fn plan(&self, input: &OpenAiRequestInput) -> Result<OpenAiRequest, OpenAiError> {
        validate_public_input(input)?;
        let spec = self.family.spec();
        if input.path_parameters.len() != spec.path_parameters.len() {
            return Err(OpenAiError::MissingConfiguration("path parameter"));
        }
        let mut path = spec.path.to_owned();
        for parameter in spec.path_parameters {
            let value = input
                .path_parameters
                .get(*parameter)
                .ok_or(OpenAiError::MissingConfiguration(parameter))?;
            path = path.replace(&format!("{{{parameter}}}"), &encode_path_segment(value));
        }
        if input
            .path_parameters
            .keys()
            .any(|parameter| !spec.path_parameters.contains(&parameter.as_str()))
        {
            return Err(OpenAiError::MissingConfiguration("unknown path parameter"));
        }

        let mut url = Url::parse(&format!("{ORIGIN}{BASE_PATH}{path}"))
            .map_err(|_| OpenAiError::MissingConfiguration("provider path"))?;
        if url.scheme() != "https"
            || url.host_str() != Some("api.openai.com")
            || url.port_or_known_default() != Some(443)
        {
            return Err(OpenAiError::MissingConfiguration("provider origin"));
        }
        let allowed_query = spec
            .allowed_query
            .iter()
            .copied()
            .collect::<BTreeMap<_, _>>();
        if input
            .query_parameters
            .keys()
            .any(|key| !allowed_query.contains_key(key.as_str()))
        {
            return Err(OpenAiError::MissingConfiguration("unknown query parameter"));
        }
        {
            let mut query = url.query_pairs_mut();
            for (input_name, value) in &input.query_parameters {
                query.append_pair(allowed_query[input_name.as_str()], value);
            }
            match spec.pagination {
                Pagination::Cursor => {
                    if let Some(cursor) = input.cursor.as_deref() {
                        query.append_pair("after", cursor);
                    }
                    query.append_pair(
                        "limit",
                        &input.page_size.unwrap_or(DEFAULT_PAGE_SIZE).to_string(),
                    );
                }
                Pagination::Page => {
                    if let Some(cursor) = input.cursor.as_deref() {
                        query.append_pair("page", cursor);
                    }
                    query.append_pair(
                        "limit",
                        &input.page_size.unwrap_or(DEFAULT_PAGE_SIZE).to_string(),
                    );
                }
                Pagination::None => {
                    if input.cursor.is_some() || input.page_size.is_some() {
                        return Err(OpenAiError::InvalidCursor);
                    }
                }
            }
        }
        Ok(OpenAiRequest {
            family: self.family.id().to_owned(),
            method: "GET".to_owned(),
            url: url.to_string(),
            accept: "application/json".to_owned(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            allow_redirects: false,
            auth: OpenAiAuthRequirement {
                operation: "openai.admin_api_key_bearer".to_owned(),
                header: "Authorization".to_owned(),
                scheme: "Bearer".to_owned(),
            },
        })
    }
}

fn validate_public_input(input: &OpenAiRequestInput) -> Result<(), OpenAiError> {
    if input
        .page_size
        .is_some_and(|size| size == 0 || size > MAX_PAGE_SIZE)
    {
        return Err(OpenAiError::MissingConfiguration("page_size"));
    }
    if let Some(cursor) = input.cursor.as_deref()
        && !safe_public_value(cursor, MAX_CURSOR_BYTES)
    {
        return Err(OpenAiError::InvalidCursor);
    }
    for (key, value) in input
        .path_parameters
        .iter()
        .chain(input.query_parameters.iter())
    {
        if !safe_public_value(key, 128) || !safe_public_value(value, MAX_CONFIG_VALUE_BYTES) {
            return Err(OpenAiError::MissingConfiguration("public request value"));
        }
        let key = key.to_ascii_lowercase();
        if [
            "api_key",
            "token",
            "authorization",
            "cookie",
            "client_secret",
            "password",
        ]
        .iter()
        .any(|marker| key.contains(marker))
        {
            return Err(OpenAiError::CredentialMaterialRejected);
        }
    }
    Ok(())
}

fn safe_public_value(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}
