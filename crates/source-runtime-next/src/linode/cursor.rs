//! Bounded, round-trippable Linode page cursors.

use super::LinodeError;

const MAX_PAGE: u32 = 1_000_000;

pub(super) fn request_page(cursor: Option<&str>) -> Result<u32, LinodeError> {
    let Some(value) = cursor else {
        return Ok(1);
    };
    let raw = value.trim();
    if raw.is_empty() {
        return Ok(1);
    }
    if raw.len() > 7
        || raw != value
        || raw.chars().any(char::is_control)
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinodeError::InvalidCursor);
    }
    let page = raw.parse::<u32>().map_err(|_| LinodeError::InvalidCursor)?;
    if page == 0 || page > MAX_PAGE || page.to_string() != raw {
        return Err(LinodeError::InvalidCursor);
    }
    Ok(page)
}

pub(super) fn next_cursor(page: u32, pages: u32) -> Result<Option<String>, LinodeError> {
    if page == 0 || pages == 0 || page > pages || pages > MAX_PAGE {
        return Err(LinodeError::InvalidResponse);
    }
    if page == pages {
        return Ok(None);
    }
    let next = page
        .checked_add(1)
        .ok_or(LinodeError::InvalidCursor)?
        .to_string();
    request_page(Some(&next))?;
    Ok(Some(next))
}
