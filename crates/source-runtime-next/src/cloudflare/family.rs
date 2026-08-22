use std::str::FromStr;

use super::CloudflareError;

/// Scope required to build one Cloudflare family request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudflareScope {
    /// Family is global to the credential-visible Cloudflare account set.
    None,
    /// Family requires one Cloudflare account identifier.
    Account,
    /// Family requires one Cloudflare zone identifier.
    Zone,
}

/// Closed Cloudflare source-catalog family vocabulary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CloudflareFamily {
    /// Cloudflare accounts.
    Account,
    /// Account members.
    Member,
    /// Account roles.
    Role,
    /// Account rulesets.
    AccountRuleset,
    /// Workers script metadata.
    WorkerScript,
    /// Account audit entries.
    AuditLog,
    /// Account-scoped Access applications.
    AccessApplication,
    /// Zone-scoped Access applications.
    ZoneAccessApplication,
    /// Account-scoped Access groups.
    AccessGroup,
    /// Zone-scoped Access groups.
    ZoneAccessGroup,
    /// Gateway rules.
    GatewayRule,
    /// Zones.
    Zone,
    /// DNS records.
    DnsRecord,
    /// Zone rulesets.
    ZoneRuleset,
    /// Zone load balancers.
    LoadBalancer,
    /// Account load-balancer pools.
    LoadBalancerPool,
}

impl CloudflareFamily {
    /// Every family in stable catalog order.
    pub const ALL: [Self; 16] = [
        Self::AccessApplication,
        Self::AccessGroup,
        Self::Account,
        Self::AccountRuleset,
        Self::AuditLog,
        Self::Member,
        Self::GatewayRule,
        Self::LoadBalancer,
        Self::LoadBalancerPool,
        Self::Role,
        Self::WorkerScript,
        Self::Zone,
        Self::ZoneAccessApplication,
        Self::ZoneAccessGroup,
        Self::ZoneRuleset,
        Self::DnsRecord,
    ];

    /// Catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Member => "member",
            Self::Role => "role",
            Self::AccountRuleset => "account_ruleset",
            Self::WorkerScript => "worker_script",
            Self::AuditLog => "audit_log",
            Self::AccessApplication => "access_application",
            Self::ZoneAccessApplication => "zone_access_application",
            Self::AccessGroup => "access_group",
            Self::ZoneAccessGroup => "zone_access_group",
            Self::GatewayRule => "gateway_rule",
            Self::Zone => "zone",
            Self::DnsRecord => "dns_record",
            Self::ZoneRuleset => "zone_ruleset",
            Self::LoadBalancer => "load_balancer",
            Self::LoadBalancerPool => "load_balancer_pool",
        }
    }

    /// Exact emitted event kind.
    pub fn event_kind(self) -> String {
        format!("cloudflare.{}", self.as_str())
    }

    /// Exact checked-in event schema.
    pub fn schema_ref(self) -> String {
        format!("cloudflare/{}/v1", self.as_str())
    }

    /// Scope required by the provider endpoint.
    pub const fn scope(self) -> CloudflareScope {
        match self {
            Self::Account | Self::Zone => CloudflareScope::None,
            Self::ZoneAccessApplication
            | Self::ZoneAccessGroup
            | Self::ZoneRuleset
            | Self::DnsRecord
            | Self::LoadBalancer => CloudflareScope::Zone,
            Self::Member
            | Self::Role
            | Self::AccountRuleset
            | Self::WorkerScript
            | Self::AuditLog
            | Self::AccessApplication
            | Self::AccessGroup
            | Self::GatewayRule
            | Self::LoadBalancerPool => CloudflareScope::Account,
        }
    }

    /// Provider list path, with the validated scope substituted by the kernel.
    pub(crate) const fn path_template(self) -> &'static str {
        match self {
            Self::Account => "/accounts",
            Self::Member => "/accounts/{scope}/members",
            Self::Role => "/accounts/{scope}/roles",
            Self::AccountRuleset => "/accounts/{scope}/rulesets",
            Self::WorkerScript => "/accounts/{scope}/workers/scripts",
            Self::AuditLog => "/accounts/{scope}/audit_logs",
            Self::AccessApplication => "/accounts/{scope}/access/apps",
            Self::ZoneAccessApplication => "/zones/{scope}/access/apps",
            Self::AccessGroup => "/accounts/{scope}/access/groups",
            Self::ZoneAccessGroup => "/zones/{scope}/access/groups",
            Self::GatewayRule => "/accounts/{scope}/gateway/rules",
            Self::Zone => "/zones",
            Self::DnsRecord => "/zones/{scope}/dns_records",
            Self::ZoneRuleset => "/zones/{scope}/rulesets",
            Self::LoadBalancer => "/zones/{scope}/load_balancers",
            Self::LoadBalancerPool => "/accounts/{scope}/load_balancers/pools",
        }
    }

    /// Optional provider detail path used to enrich list records.
    pub const fn detail_path_template(self) -> Option<&'static str> {
        match self {
            Self::Role => Some("/accounts/{scope}/roles/{id}"),
            Self::AccountRuleset => Some("/accounts/{scope}/rulesets/{id}"),
            Self::ZoneRuleset => Some("/zones/{scope}/rulesets/{id}"),
            _ => None,
        }
    }

    pub(crate) const fn id_attribute(self) -> &'static str {
        match self {
            Self::Account => "account_id",
            Self::Member => "member_id",
            Self::Role => "role_id",
            Self::AccountRuleset | Self::ZoneRuleset => "ruleset_id",
            Self::WorkerScript => "script_id",
            Self::AuditLog => "audit_id",
            Self::AccessApplication | Self::ZoneAccessApplication => "application_id",
            Self::AccessGroup | Self::ZoneAccessGroup => "group_id",
            Self::GatewayRule => "rule_id",
            Self::Zone => "zone_id",
            Self::DnsRecord => "record_id",
            Self::LoadBalancer => "load_balancer_id",
            Self::LoadBalancerPool => "pool_id",
        }
    }
}

impl FromStr for CloudflareFamily {
    type Err = CloudflareError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|family| family.as_str() == value.trim())
            .ok_or(CloudflareError::InvalidFamily)
    }
}
