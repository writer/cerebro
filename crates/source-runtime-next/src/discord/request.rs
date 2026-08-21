use std::net::IpAddr;

use reqwest::Url;

use super::{DiscordError, DiscordFamily, DiscordKernel, DiscordRequest, wire::MAX_RESPONSE_BYTES};

const AUDIT_DEFAULT_PAGE_SIZE: usize = 50;
const AUDIT_MAX_PAGE_SIZE: usize = 100;
const MEMBER_DEFAULT_PAGE_SIZE: usize = 1;
const MEMBER_MAX_PAGE_SIZE: usize = 1_000;
const MAX_SNOWFLAKE_BYTES: usize = 20;
const MAX_TENANT_ID_BYTES: usize = 128;

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
    /// Return the provider method for this read-only operation.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the bot-token authorization scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bot"
    }

    /// Return the header the trusted host must populate from its credential lease.
    pub const fn authorization_header(&self) -> &'static str {
        "Authorization"
    }

    /// The portable request never contains credential bytes.
    pub const fn contains_credentials(&self) -> bool {
        false
    }

    /// Redirects are denied so authentication cannot escape the planned origin.
    pub const fn allows_redirects(&self) -> bool {
        false
    }

    /// Return the provider permission required for audit-log reads.
    pub const fn required_permission(&self) -> Option<&'static str> {
        match self.family {
            DiscordFamily::AuditLog => Some("VIEW_AUDIT_LOG"),
            _ => None,
        }
    }

    /// Return the response byte bound the host must enforce before kernel decode.
    pub const fn max_response_bytes(&self) -> usize {
        MAX_RESPONSE_BYTES
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

impl DiscordKernel {
    /// Build a kernel for one authenticated tenant, guild, and family.
    ///
    /// The caller still owns egress authorization and the operation-scoped bot
    /// credential lease. `application_id` is required only for `permission`.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        guild_id: &str,
        application_id: Option<&str>,
        family: DiscordFamily,
        page_size: Option<usize>,
    ) -> Result<Self, DiscordError> {
        let base_url = validate_base_url(base_url)?;
        let tenant_id = validate_tenant_id(tenant_id)?;
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
            tenant_id,
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
            operation_path: path,
            tenant_id: self.tenant_id.clone(),
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
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DiscordError::InvalidBaseUrl);
    }
    if let Some(host) = url.host_str() {
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        if normalized == "localhost"
            || normalized.ends_with(".localhost")
            || normalized.ends_with(".local")
            || !normalized.contains('.')
        {
            return Err(DiscordError::UnsafeOrigin);
        }
        if let Ok(address) = normalized.parse::<IpAddr>()
            && unsafe_address(address)
        {
            return Err(DiscordError::UnsafeOrigin);
        }
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url)
}

fn unsafe_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn validate_tenant_id(value: &str) -> Result<String, DiscordError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_TENANT_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(DiscordError::InvalidTenantId);
    }
    Ok(value.to_owned())
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
