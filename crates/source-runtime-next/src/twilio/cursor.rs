//! Opaque Twilio provider continuation validation and decoding.

use reqwest::Url;
use serde_json::{Map, Value};

use super::TwilioError;

const MAX_CURSOR_BYTES: usize = 4_096;

pub(super) fn bounded_cursor(cursor: Option<&str>) -> Result<Option<String>, TwilioError> {
    let cursor = cursor.map(str::trim).filter(|value| !value.is_empty());
    if cursor.is_some_and(|value| {
        value.len() > MAX_CURSOR_BYTES
            || value.chars().any(char::is_control)
            || value.starts_with("http://")
            || value.starts_with("https://")
    }) {
        return Err(TwilioError::InvalidCursor);
    }
    Ok(cursor.map(str::to_owned))
}

pub(super) fn response_cursor(object: &Map<String, Value>) -> Result<Option<String>, TwilioError> {
    const KEYS: [&str; 7] = [
        "nextCursor",
        "next_cursor",
        "cursor",
        "next",
        "nextPageToken",
        "next_page_token",
        "next_page",
    ];
    for key in KEYS {
        if let Some(value) = object.get(key) {
            let cursor = bounded_cursor(response_cursor_value(value)?.as_deref())?;
            if cursor.is_some() {
                return Ok(cursor);
            }
        }
    }
    for container in [
        "pagination",
        "page",
        "pageInfo",
        "meta",
        "result_info",
        "resultInfo",
    ] {
        let Some(Value::Object(nested)) = object.get(container) else {
            continue;
        };
        for key in KEYS {
            if let Some(value) = nested.get(key) {
                let cursor = bounded_cursor(response_cursor_value(value)?.as_deref())?;
                if cursor.is_some() {
                    return Ok(cursor);
                }
            }
        }
        if let Some(next) = next_page_cursor(nested)? {
            return bounded_cursor(Some(&next));
        }
    }
    Ok(None)
}

fn response_cursor_value(value: &Value) -> Result<Option<String>, TwilioError> {
    let Some(value) = cursor_scalar(value)? else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() || value.starts_with("http://") || value.starts_with("https://") {
        return Ok((!value.is_empty()).then(|| value.to_owned()));
    }
    let base = Url::parse("https://twilio.invalid/").map_err(|_| TwilioError::InvalidResponse)?;
    let parsed = base.join(value).map_err(|_| TwilioError::InvalidCursor)?;
    if let Some((_, cursor)) = parsed
        .query_pairs()
        .find(|(name, value)| name == "cursor" && !value.trim().is_empty())
    {
        return Ok(Some(cursor.into_owned()));
    }
    Ok(Some(value.to_owned()))
}

fn cursor_scalar(value: &Value) -> Result<Option<String>, TwilioError> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        Value::Number(value) => Ok(Some(value.to_string())),
        _ => Err(TwilioError::InvalidResponse),
    }
}

fn next_page_cursor(object: &Map<String, Value>) -> Result<Option<String>, TwilioError> {
    let Some(page) = object.get("page") else {
        return Ok(None);
    };
    let total = object
        .get("total_pages")
        .or_else(|| object.get("totalPages"))
        .or_else(|| object.get("page_count"))
        .or_else(|| object.get("pageCount"));
    let Some(total) = total else {
        return Ok(None);
    };
    let page = positive_integer(page)?;
    let total = positive_integer(total)?;
    if page >= total {
        return Ok(None);
    }
    Ok(Some((page + 1).to_string()))
}

fn positive_integer(value: &Value) -> Result<u64, TwilioError> {
    let parsed = match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.trim().parse().ok(),
        _ => None,
    };
    parsed
        .filter(|value| *value > 0)
        .ok_or(TwilioError::InvalidResponse)
}
