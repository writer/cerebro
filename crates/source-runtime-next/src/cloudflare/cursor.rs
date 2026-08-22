use serde_json::{Map, Value};

use super::CloudflareError;

const MAX_PAGES: u32 = 10_000;

pub(super) fn parse_cursor(cursor: Option<&str>) -> Result<u32, CloudflareError> {
    let Some(value) = cursor.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(1);
    };
    value
        .parse::<u32>()
        .ok()
        .filter(|page| (1..=MAX_PAGES).contains(page))
        .ok_or(CloudflareError::InvalidCursor)
}

pub(super) fn next_cursor(
    result_info: Option<&Value>,
    request_page: u32,
    request_page_size: usize,
    record_count: usize,
) -> Result<Option<String>, CloudflareError> {
    let Some(info) = result_info else {
        return Ok(
            (record_count == request_page_size && request_page < MAX_PAGES)
                .then(|| (request_page + 1).to_string()),
        );
    };
    if info.is_null() {
        return Ok(None);
    }
    let info = info.as_object().ok_or(CloudflareError::InvalidResponse)?;
    let page = u32_at(info, "page").ok_or(CloudflareError::InvalidResponse)?;
    let total_pages = u32_at(info, "total_pages").ok_or(CloudflareError::InvalidResponse)?;
    if page != request_page || total_pages == 0 || total_pages > MAX_PAGES || page > total_pages {
        return Err(CloudflareError::InvalidCursor);
    }
    Ok((page < total_pages).then(|| (page + 1).to_string()))
}

fn u32_at(object: &Map<String, Value>, key: &str) -> Option<u32> {
    object
        .get(key)
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
        .and_then(|value| u32::try_from(value).ok())
}
