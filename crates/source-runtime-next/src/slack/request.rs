use std::net::IpAddr;

use reqwest::Url;

use super::{
    SlackError, SlackFamily, SlackFilters, SlackKernel, SlackRequest,
    cursor::{self, ParsedCursor},
};

pub(super) fn origin(value: &str) -> Result<Url, SlackError> {
    let value = value.trim().trim_end_matches('/');
    let parsed = Url::parse(value).map_err(|_| SlackError::InvalidOrigin)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.port_or_known_default() != Some(443)
    {
        return Err(SlackError::InvalidOrigin);
    }
    if let Some(host) = parsed.host_str()
        && let Ok(ip) = host.parse::<IpAddr>()
        && (ip.is_loopback() || ip.is_unspecified() || is_private(ip))
    {
        return Err(SlackError::InvalidOrigin);
    }
    Ok(parsed)
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_broadcast(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

pub(super) fn safe_component(value: &str, maximum: usize) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= maximum
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

pub(super) fn validate_filters(
    family: SlackFamily,
    filters: &SlackFilters,
) -> Result<(), SlackError> {
    if family == SlackFamily::ChannelMember
        && filters
            .channel_id
            .as_deref()
            .is_none_or(|value| !safe_component(value, 256))
    {
        return Err(SlackError::MissingScope);
    }
    if family == SlackFamily::UserGroupMember
        && filters
            .usergroup_id
            .as_deref()
            .is_none_or(|value| !safe_component(value, 256))
    {
        return Err(SlackError::MissingScope);
    }
    for value in [
        &filters.before,
        &filters.action,
        &filters.actor,
        &filters.entity,
        &filters.oldest,
        &filters.latest,
    ]
    .into_iter()
    .flatten()
    {
        if !safe_component(value, 2_048) {
            return Err(SlackError::MissingScope);
        }
    }
    for value in [&filters.oldest, &filters.latest].into_iter().flatten() {
        if !cursor::unix_seconds(value) {
            return Err(SlackError::InvalidCursor);
        }
    }
    Ok(())
}

pub(super) fn plan(kernel: &SlackKernel, cursor: Option<&str>) -> Result<SlackRequest, SlackError> {
    let parsed_cursor = cursor::parse(kernel.family, cursor)?;
    let base = if kernel.family.uses_audit_origin() {
        &kernel.audit_origin
    } else {
        &kernel.web_origin
    };
    let mut url = Url::parse(&format!(
        "{}{}",
        base.as_str().trim_end_matches('/'),
        kernel.family.path()
    ))
    .map_err(|_| SlackError::InvalidOrigin)?;
    if url.origin() != base.origin() {
        return Err(SlackError::InvalidOrigin);
    }
    add_query(kernel, &parsed_cursor, &mut url)?;
    let audit_window = parsed_cursor.audit_window.or_else(|| {
        (kernel.family == SlackFamily::AuditLog)
            .then(|| {
                Some((
                    kernel.filters.oldest.clone()?,
                    kernel.filters.latest.clone()?,
                ))
            })
            .flatten()
    });
    Ok(SlackRequest {
        family: kernel.family,
        url,
        method: kernel.family.method(),
        page_size: kernel.page_size,
        audit_window,
    })
}

fn add_query(kernel: &SlackKernel, cursor: &ParsedCursor, url: &mut Url) -> Result<(), SlackError> {
    let mut pairs = Vec::<(&str, String)>::new();
    match kernel.family {
        SlackFamily::Team | SlackFamily::User => {
            pairs.push(("limit", kernel.page_size.to_string()));
        }
        SlackFamily::Channel => {
            pairs.extend([
                ("exclude_archived", "false".to_owned()),
                ("limit", kernel.page_size.to_string()),
                ("types", "public_channel,private_channel".to_owned()),
            ]);
        }
        SlackFamily::UserGroup => {}
        SlackFamily::AccessLog => {
            pairs.push(("count", kernel.page_size.to_string()));
            pairs.push((
                "page",
                if cursor.token.is_empty() {
                    "1".to_owned()
                } else {
                    cursor.token.clone()
                },
            ));
            add_optional(&mut pairs, "before", kernel.filters.before.as_ref());
        }
        SlackFamily::ChannelMember => {
            pairs.push((
                "channel",
                kernel
                    .filters
                    .channel_id
                    .clone()
                    .ok_or(SlackError::MissingScope)?,
            ));
            pairs.push(("limit", kernel.page_size.to_string()));
        }
        SlackFamily::UserGroupMember => {
            pairs.push(("include_disabled", "true".to_owned()));
            pairs.push(("limit", kernel.page_size.to_string()));
            pairs.push((
                "usergroup",
                kernel
                    .filters
                    .usergroup_id
                    .clone()
                    .ok_or(SlackError::MissingScope)?,
            ));
        }
        SlackFamily::AuditLog => {
            pairs.push(("limit", kernel.page_size.to_string()));
            add_optional(&mut pairs, "action", kernel.filters.action.as_ref());
            add_optional(&mut pairs, "actor", kernel.filters.actor.as_ref());
            add_optional(&mut pairs, "entity", kernel.filters.entity.as_ref());
            let window = cursor.audit_window.as_ref();
            let oldest = window
                .map(|value| &value.0)
                .or(kernel.filters.oldest.as_ref());
            let latest = window
                .map(|value| &value.1)
                .or(kernel.filters.latest.as_ref());
            add_optional(&mut pairs, "oldest", oldest);
            add_optional(&mut pairs, "latest", latest);
        }
    }
    if !cursor.token.is_empty() && kernel.family != SlackFamily::AccessLog {
        pairs.push(("cursor", cursor.token.clone()));
    }
    pairs.sort_by(|left, right| left.0.cmp(right.0));
    if !pairs.is_empty() {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, &value);
        }
    }
    Ok(())
}

fn add_optional(
    pairs: &mut Vec<(&'static str, String)>,
    key: &'static str,
    value: Option<&String>,
) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        pairs.push((key, value.trim().to_owned()));
    }
}
