use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;

use super::{
    AnthropicError, AnthropicKernel, AnthropicPage, AnthropicRequest,
    family::PaginationKind,
    normalize::normalize_record,
    request::{MAX_RECORDS, MAX_RESPONSE_BYTES},
};

impl AnthropicKernel {
    /// Classify a provider status and decode a bounded response body.
    pub fn decode_http(
        &self,
        request: &AnthropicRequest,
        status: u16,
        body: &[u8],
        observed_at: &str,
    ) -> Result<AnthropicPage, AnthropicError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(AnthropicError::ResponseTooLarge);
        }
        if request.family != self.family || request != &self.plan(request.cursor.as_deref())? {
            return Err(AnthropicError::RequestScopeMismatch);
        }
        match status {
            200 => self.decode_success(request, body, observed_at),
            401 => Err(AnthropicError::AuthenticationRejected),
            403 => Err(AnthropicError::RequiredProviderScopeMissing),
            429 => Err(AnthropicError::ProviderRateLimit),
            500..=599 => Err(AnthropicError::ProviderUnavailable),
            _ => Err(AnthropicError::UnexpectedProviderStatus),
        }
    }

    /// Decode a successful provider response for a request planned by this kernel.
    pub fn decode(
        &self,
        request: &AnthropicRequest,
        body: &[u8],
        observed_at: &str,
    ) -> Result<AnthropicPage, AnthropicError> {
        self.decode_http(request, 200, body, observed_at)
    }

    fn decode_success(
        &self,
        request: &AnthropicRequest,
        body: &[u8],
        observed_at: &str,
    ) -> Result<AnthropicPage, AnthropicError> {
        let response: Value =
            serde_json::from_slice(body).map_err(|_| AnthropicError::MalformedResponse)?;
        let payloads = records(self.family, &response)?;
        if payloads.len() > self.page_size || payloads.len() > MAX_RECORDS {
            return Err(AnthropicError::ResponseTooLarge);
        }
        let mut seen = BTreeMap::<String, Value>::new();
        let mut normalized = Vec::with_capacity(payloads.len());
        for payload in payloads {
            let record = normalize_record(
                self.family,
                &self.tenant_id,
                self.base_url.as_str().trim_end_matches('/'),
                &request.operation_path,
                &self.scope.path_parameters,
                observed_at,
                payload,
            )?;
            match seen.get(&record.provider_id) {
                Some(existing) if existing == &record.payload => continue,
                Some(_) => return Err(AnthropicError::DuplicateConflict),
                None => {
                    seen.insert(record.provider_id.clone(), record.payload.clone());
                    normalized.push(record);
                }
            }
        }
        let next_cursor = continuation(self, &response)?;
        let checkpoint_cursor = normalized.last().map(|record| {
            next_cursor
                .clone()
                .unwrap_or_else(|| record.provider_id.clone())
        });
        let watermark = normalized.last().map(|record| record.occurred_at.clone());
        Ok(AnthropicPage {
            records: normalized,
            next_cursor,
            checkpoint_cursor,
            watermark,
        })
    }
}

fn records(family: super::AnthropicFamily, response: &Value) -> Result<Vec<Value>, AnthropicError> {
    if let Some(records) = response.as_array() {
        return Ok(records.clone());
    }
    let object = response
        .as_object()
        .ok_or(AnthropicError::MalformedResponse)?;
    if family.singleton() {
        for key in ["data", "result", "item", "record"] {
            if let Some(value) = object.get(key).filter(|value| value.is_object()) {
                return Ok(vec![value.clone()]);
            }
        }
        return Ok(vec![response.clone()]);
    }
    let compact = family.as_str().replace('_', "");
    let mut keys = family.list_keys().to_vec();
    keys.extend(["data", "items", "results", "records", family.as_str()]);
    let plural = format!("{}s", family.as_str());
    let compact_plural = format!("{compact}s");
    for key in keys
        .into_iter()
        .map(str::to_owned)
        .chain([plural, compact, compact_plural])
    {
        if let Some(values) = object.get(&key).and_then(Value::as_array) {
            return Ok(values.clone());
        }
    }
    Err(AnthropicError::MalformedResponse)
}

fn continuation(
    kernel: &AnthropicKernel,
    response: &Value,
) -> Result<Option<String>, AnthropicError> {
    if kernel.family.pagination() == PaginationKind::None {
        return Ok(None);
    }
    let Some(object) = response.as_object() else {
        return Ok(None);
    };
    if object.get("has_more").and_then(Value::as_bool) == Some(false) {
        return Ok(None);
    }
    let raw = ["last_id", "next_page", "next_cursor", "cursor"]
        .iter()
        .find_map(|key| object.get(*key).and_then(scalar_string))
        .or_else(|| {
            ["pagination", "page", "meta"]
                .iter()
                .filter_map(|key| object.get(*key).and_then(Value::as_object))
                .find_map(|nested| {
                    ["last_id", "next_page", "next_cursor", "cursor", "next"]
                        .iter()
                        .find_map(|key| nested.get(*key).and_then(scalar_string))
                })
        });
    raw.map(|value| normalize_continuation(kernel, &value))
        .transpose()
}

fn normalize_continuation(kernel: &AnthropicKernel, raw: &str) -> Result<String, AnthropicError> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 4_096 || raw.chars().any(char::is_control) {
        return Err(AnthropicError::InvalidCursor);
    }
    let cursor = if let Ok(url) = Url::parse(raw) {
        if url.origin() != kernel.base_url.origin() {
            return Err(AnthropicError::InvalidCursor);
        }
        let key = match kernel.family.pagination() {
            PaginationKind::Page => "page",
            PaginationKind::AfterId => "after_id",
            PaginationKind::None => return Err(AnthropicError::InvalidCursor),
        };
        url.query_pairs()
            .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
            .ok_or(AnthropicError::InvalidCursor)?
    } else {
        raw.to_owned()
    };
    kernel.plan(Some(&cursor))?;
    Ok(cursor)
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}
