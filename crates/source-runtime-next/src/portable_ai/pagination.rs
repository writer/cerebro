use std::collections::HashMap;

use reqwest::Url;
use serde_json::Value;

use crate::source_execution::SourceExecutionError;

use super::normalize::scalar_at;

pub(super) fn validated_continuation(
    origin: &str,
    value: &str,
) -> Result<Url, SourceExecutionError> {
    let origin = Url::parse(origin).map_err(|_| SourceExecutionError::InvalidPlan)?;
    let continuation = Url::parse(value).map_err(|_| SourceExecutionError::InvalidCursor)?;
    let prefix = origin.path().trim_end_matches('/');
    if continuation.scheme() != origin.scheme()
        || continuation.host_str() != origin.host_str()
        || continuation.port_or_known_default() != origin.port_or_known_default()
        || continuation.username() != ""
        || continuation.password().is_some()
        || continuation.fragment().is_some()
        || (!prefix.is_empty()
            && continuation.path() != prefix
            && !continuation.path().starts_with(&format!("{prefix}/")))
    {
        return Err(SourceExecutionError::EgressDenied);
    }
    Ok(continuation)
}

pub(super) fn response_header<'a>(
    headers: &'a HashMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
}

pub(super) fn link_next(value: &str) -> Option<String> {
    value.split(',').find_map(|part| {
        let part = part.trim();
        let (target, parameters) = part.split_once('>')?;
        if !parameters.split(';').any(|parameter| {
            parameter.trim().eq_ignore_ascii_case("rel=\"next\"")
                || parameter.trim().eq_ignore_ascii_case("rel=next")
        }) {
            return None;
        }
        target
            .trim()
            .strip_prefix('<')
            .map(str::to_owned)
            .filter(|target| !target.is_empty())
    })
}

pub(super) fn next_page(document: &Value) -> Result<Option<String>, SourceExecutionError> {
    let current = scalar_at(document, &["$.meta.page".to_owned()])
        .ok_or(SourceExecutionError::MalformedResponse)?
        .parse::<usize>()
        .map_err(|_| SourceExecutionError::MalformedResponse)?;
    let total = scalar_at(document, &["$.meta.totalPages".to_owned()])
        .ok_or(SourceExecutionError::MalformedResponse)?
        .parse::<usize>()
        .map_err(|_| SourceExecutionError::MalformedResponse)?;
    if current == 0 || total > 10_000_000 {
        return Err(SourceExecutionError::InvalidCursor);
    }
    Ok((current < total).then(|| (current + 1).to_string()))
}
