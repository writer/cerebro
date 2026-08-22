//! Go-compatible Okta continuation validation.

use reqwest::Url;

use super::{OktaError, OktaFamily, OktaRequest};

const MAX_CURSOR_BYTES: usize = 4_096;

pub(super) fn bounded_cursor(cursor: Option<&str>) -> Result<Option<String>, OktaError> {
    let cursor = cursor.map(str::trim).filter(|value| !value.is_empty());
    if cursor.is_some_and(|value| {
        value.len() > MAX_CURSOR_BYTES
            || value.chars().any(char::is_control)
            || value.starts_with("http://")
            || value.starts_with("https://")
    }) {
        return Err(OktaError::InvalidCursor);
    }
    Ok(cursor.map(str::to_owned))
}

pub(super) fn assignment_cursor(
    cursor: Option<&str>,
) -> Result<(&'static str, Option<String>), OktaError> {
    let cursor = bounded_cursor(cursor)?;
    let Some(cursor) = cursor.as_deref() else {
        return Ok(("users", None));
    };
    if let Some((phase, value)) = cursor.split_once(':') {
        let phase = match phase.trim() {
            "users" => Some("users"),
            "groups" => Some("groups"),
            _ => None,
        };
        if let Some(phase) = phase {
            return Ok((phase, bounded_cursor(Some(value))?));
        }
    }
    Ok(("users", Some(cursor.to_owned())))
}

pub(super) fn next_cursor(
    request: &OktaRequest,
    base_origin: &str,
    link_header: Option<&str>,
) -> Result<Option<String>, OktaError> {
    let Some(header) = link_header.map(str::trim).filter(|value| !value.is_empty()) else {
        if request.family == OktaFamily::AppAssignment
            && request.assignment_phase.as_deref() == Some("users")
        {
            return Ok(Some("groups:".to_owned()));
        }
        return Ok(None);
    };
    if header.len() > MAX_CURSOR_BYTES * 2 || header.chars().any(char::is_control) {
        return Err(OktaError::InvalidCursor);
    }
    for part in header.split(',') {
        let part = part.trim();
        let Some(close) = part.find('>') else {
            continue;
        };
        let Some(raw_url) = part.get(1..close).filter(|_| part.starts_with('<')) else {
            continue;
        };
        if !part.get(close + 1..).is_some_and(|params| {
            params.split(';').any(|param| {
                let param = param.trim().replace('"', "");
                param == "rel=next"
            })
        }) {
            continue;
        }
        let url = Url::parse(raw_url)
            .or_else(|_| request.url.join(raw_url))
            .map_err(|_| OktaError::InvalidCursor)?;
        if url.origin().unicode_serialization() != base_origin
            || url.path() != request.url.path()
            || url.fragment().is_some()
        {
            return Err(OktaError::InvalidCursor);
        }
        let after = url
            .query_pairs()
            .find_map(|(name, value)| (name == "after").then(|| value.into_owned()))
            .ok_or(OktaError::InvalidCursor)?;
        let after = bounded_cursor(Some(&after))?.ok_or(OktaError::InvalidCursor)?;
        if request.family == OktaFamily::AppAssignment {
            let phase = request.assignment_phase.as_deref().unwrap_or("users");
            return Ok(Some(format!("{phase}:{after}")));
        }
        return Ok(Some(after));
    }
    if request.family == OktaFamily::AppAssignment
        && request.assignment_phase.as_deref() == Some("users")
    {
        return Ok(Some("groups:".to_owned()));
    }
    Ok(None)
}
