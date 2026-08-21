use std::net::IpAddr;

use reqwest::Url;

use super::{DiscordError, DiscordFamily, DiscordKernel, DiscordRequest};

const AUDIT_DEFAULT_PAGE_SIZE: usize = 50;
const AUDIT_MAX_PAGE_SIZE: usize = 100;
const MEMBER_DEFAULT_PAGE_SIZE: usize = 1;
const MEMBER_MAX_PAGE_SIZE: usize = 1_000;
const MAX_SNOWFLAKE_BYTES: usize = 20;

impl DiscordFamily {
    const fn default_page_size(self) -> Option<usize> {
        match self {
            Self::AuditLog => Some(AUDIT_DEFAULT_PAGE_SIZE),
            Self::Member => Some(MEMBER_DEFAULT_PAGE_SIZE),
            Self::Role | Self::Permission => None,
        }
    }

    const fn max_page_size(self) -> Option<usize> {
        match self {
            Self::AuditLog => Some(AUDIT_MAX_PAGE_SIZE),
            Self::Member => Some(MEMBER_MAX_PAGE_SIZE),
            Self::Role | Self::Permission => None,
        }
    }
}

impl DiscordRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the bot-token authorization scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bot"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

impl DiscordKernel {
    /// Build a kernel for one guild, family, and optional application.
    ///
    /// The caller still owns egress authorization and the operation-scoped bot
    /// credential lease. `application_id` is required only for `permission`.
    pub fn new(
        base_url: &str,
        guild_id: &str,
        application_id: Option<&str>,
        family: DiscordFamily,
        page_size: Option<usize>,
    ) -> Result<Self, DiscordError> {
        let base_url = validate_base_url(base_url)?;
        let guild_id = snowflake(guild_id, DiscordError::InvalidGuildId)?;
        let application_id = application_id
            .map(|value| snowflake(value, DiscordError::InvalidApplicationId))
            .transpose()?;
        if family == DiscordFamily::Permission && application_id.is_none() {
            return Err(DiscordError::MissingApplicationId);
        }
        let page_size = match family.max_page_size() {
            Some(maximum) => {
                let value = page_size.or(family.default_page_size()).unwrap_or_default();
                if !(1..=maximum).contains(&value) {
                    return Err(DiscordError::InvalidPageSize);
                }
                Some(value)
            }
            None if page_size.is_some() => return Err(DiscordError::UnsupportedPageSize),
            None => None,
        };
        Ok(Self {
            base_url,
            guild_id,
            application_id,
            family,
            page_size,
        })
    }

    /// Plan one credential-free provider request.
    ///
    /// Paged families start at `after=0`, which makes audit results ascend by
    /// entry ID and member results advance from the highest previous user ID.
    pub fn plan(&self, cursor: Option<&str>) -> Result<DiscordRequest, DiscordError> {
        let cursor = match (self.page_size, cursor) {
            (Some(_), Some(value)) => Some(snowflake(value, DiscordError::InvalidCursor)?),
            (Some(_), None) => None,
            (None, Some(value)) if !value.trim().is_empty() => {
                return Err(DiscordError::UnsupportedCursor);
            }
            (None, _) => None,
        };
        let path = match self.family {
            DiscordFamily::AuditLog => format!("/guilds/{}/audit-logs", self.guild_id),
            DiscordFamily::Member => format!("/guilds/{}/members", self.guild_id),
            DiscordFamily::Role => format!("/guilds/{}/roles", self.guild_id),
            DiscordFamily::Permission => format!(
                "/applications/{}/guilds/{}/commands/permissions",
                self.application_id.as_deref().unwrap_or_default(),
                self.guild_id
            ),
        };
        let mut url = self.endpoint(&path);
        if let Some(page_size) = self.page_size {
            let mut query = url.query_pairs_mut();
            query.append_pair("after", cursor.as_deref().unwrap_or("0"));
            query.append_pair("limit", &page_size.to_string());
        }
        Ok(DiscordRequest {
            url,
            family: self.family,
            cursor,
        })
    }

    fn endpoint(&self, suffix: &str) -> Url {
        let mut url = self.base_url.clone();
        let path = format!("{}{}", self.base_url.path().trim_end_matches('/'), suffix);
        url.set_path(&path);
        url.set_query(None);
        url.set_fragment(None);
        url
    }
}

fn validate_base_url(value: &str) -> Result<Url, DiscordError> {
    let mut url = Url::parse(value.trim()).map_err(|_| DiscordError::InvalidBaseUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DiscordError::InvalidBaseUrl);
    }
    if let Some(host) = url.host_str()
        && let Ok(address) = host.parse::<IpAddr>()
        && unsafe_address(address)
    {
        return Err(DiscordError::UnsafeOrigin);
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url)
}

fn unsafe_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
        }
    }
}

pub(super) fn snowflake(value: &str, error: DiscordError) -> Result<String, DiscordError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_SNOWFLAKE_BYTES
        || value
            .parse::<u64>()
            .ok()
            .filter(|number| *number > 0)
            .is_none()
    {
        return Err(error);
    }
    Ok(value.to_owned())
}
