use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{CloudflareError, CloudflareFamily};

const MAX_NESTING_DEPTH: usize = 64;

pub(super) fn bounded_component(value: &str, maximum: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
        && !value.contains('/')
        && !value.contains('?')
        && !value.contains('#'))
    .then(|| value.to_owned())
}

pub(super) fn string_at(object: &Map<String, Value>, key: &str) -> Option<String> {
    value_string(object.get(key)?)
}

pub(super) fn string_path(object: &Map<String, Value>, path: &str) -> Option<String> {
    value_string_at(object, path)
}

pub(super) fn value_string_at(object: &Map<String, Value>, path: &str) -> Option<String> {
    let mut value = Value::Object(object.clone());
    for part in path.split('.') {
        value = value.get(part)?.clone();
    }
    value_string(&value)
}

fn value_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => nonempty(value),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Array(values) => {
            let values = values.iter().filter_map(value_string).collect::<Vec<_>>();
            (!values.is_empty()).then(|| values.join(","))
        }
        Value::Object(_) => serde_json::to_string(value).ok(),
    }
}

fn nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

pub(super) fn common_attributes(
    family: CloudflareFamily,
    provider_id: &str,
    tenant_id: &str,
) -> BTreeMap<String, String> {
    let resource_type = if family == CloudflareFamily::Member {
        "identity_user"
    } else {
        family.as_str()
    };
    BTreeMap::from([
        ("external_id".to_owned(), provider_id.to_owned()),
        ("family".to_owned(), family.as_str().to_owned()),
        ("provider".to_owned(), "cloudflare".to_owned()),
        ("resource_id".to_owned(), provider_id.to_owned()),
        ("resource_type".to_owned(), resource_type.to_owned()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("source_product".to_owned(), "cloudflare".to_owned()),
        ("source_provider".to_owned(), "cloudflare".to_owned()),
        ("source_system".to_owned(), "cloudflare".to_owned()),
        ("tenant_id".to_owned(), tenant_id.to_owned()),
    ])
}

pub(super) fn attribute_contract(
    family: CloudflareFamily,
) -> &'static [(&'static str, &'static [&'static str])] {
    match family {
        CloudflareFamily::Account => &[
            ("account_id", &["id"]),
            ("name", &["name"]),
            ("type", &["type"]),
            ("resource_name", &["name", "id"]),
            ("observed_at", &["modified_on", "created_on"]),
        ],
        CloudflareFamily::Member => &[
            ("member_id", &["id"]),
            ("account_id", &["account.id", "account_id"]),
            ("email", &["user.email", "email"]),
            ("status", &["status"]),
            ("roles", &["roles"]),
            ("resource_name", &["user.name", "id"]),
            ("observed_at", &["modified_on", "created_on"]),
        ],
        CloudflareFamily::Role => &[
            ("role_id", &["id"]),
            ("name", &["name"]),
            ("description", &["description"]),
            ("permissions", &["permissions"]),
            ("permission_groups", &["permission_groups"]),
            ("resource_name", &["name", "id"]),
        ],
        CloudflareFamily::AccountRuleset | CloudflareFamily::ZoneRuleset => &[
            ("ruleset_id", &["id"]),
            ("name", &["name"]),
            ("kind", &["kind"]),
            ("phase", &["phase"]),
            ("version", &["version"]),
            ("last_updated", &["last_updated"]),
            ("rules", &["rules"]),
            ("resource_name", &["name", "id"]),
            ("observed_at", &["last_updated"]),
        ],
        CloudflareFamily::WorkerScript => &[
            ("script_id", &["id"]),
            ("created_on", &["created_on"]),
            ("modified_on", &["modified_on"]),
            ("compatibility_date", &["compatibility_date"]),
            ("tags", &["tags"]),
            ("bindings", &["bindings"]),
            ("placement", &["placement"]),
            ("resource_name", &["id", "name"]),
            ("observed_at", &["modified_on", "created_on"]),
        ],
        CloudflareFamily::AuditLog => &[
            ("audit_id", &["id"]),
            ("account_id", &["account.id", "account_id"]),
            ("action", &["action.type", "action"]),
            ("actor_email", &["actor.email"]),
            ("actor_ip", &["actor.ip"]),
            ("resource_id", &["resource.id"]),
            ("resource_type", &["resource.type"]),
            ("zone_id", &["zone.id", "zone_id"]),
            ("resource_name", &["action.type", "id"]),
            ("observed_at", &["when", "timestamp"]),
        ],
        CloudflareFamily::AccessApplication | CloudflareFamily::ZoneAccessApplication => &[
            ("application_id", &["id"]),
            ("name", &["name"]),
            ("domain", &["domain"]),
            ("type", &["type"]),
            ("aud", &["aud"]),
            ("session_duration", &["session_duration"]),
            ("policies", &["policies"]),
            ("allowed_idps", &["allowed_idps"]),
            ("auto_redirect_to_identity", &["auto_redirect_to_identity"]),
            ("resource_name", &["name", "domain", "id"]),
            ("observed_at", &["updated_at", "created_at"]),
        ],
        CloudflareFamily::AccessGroup | CloudflareFamily::ZoneAccessGroup => &[
            ("group_id", &["id"]),
            ("name", &["name"]),
            ("include", &["include"]),
            ("exclude", &["exclude"]),
            ("require", &["require"]),
            ("resource_name", &["name", "id"]),
            ("observed_at", &["updated_at", "created_at"]),
        ],
        CloudflareFamily::GatewayRule => &[
            ("rule_id", &["id"]),
            ("name", &["name"]),
            ("action", &["action"]),
            ("traffic", &["traffic"]),
            ("enabled", &["enabled"]),
            ("precedence", &["precedence"]),
            ("filters", &["filters"]),
            ("rule_settings", &["rule_settings"]),
            ("resource_name", &["name", "id"]),
            ("observed_at", &["updated_at", "created_at"]),
        ],
        CloudflareFamily::Zone => &[
            ("zone_id", &["id"]),
            ("account_id", &["account.id", "account_id"]),
            ("name", &["name"]),
            ("status", &["status"]),
            ("type", &["type"]),
            ("paused", &["paused"]),
            ("resource_name", &["name", "id"]),
            ("observed_at", &["modified_on", "created_on"]),
        ],
        CloudflareFamily::DnsRecord => &[
            ("record_id", &["id"]),
            ("name", &["name"]),
            ("type", &["type"]),
            ("content", &["content"]),
            ("proxied", &["proxied"]),
            ("resource_name", &["name", "id"]),
            ("observed_at", &["modified_on", "created_on"]),
        ],
        CloudflareFamily::LoadBalancer => &[
            ("load_balancer_id", &["id"]),
            ("name", &["name"]),
            ("fallback_pool", &["fallback_pool"]),
            ("default_pools", &["default_pools"]),
            ("enabled", &["enabled"]),
            ("proxied", &["proxied"]),
            ("steering_policy", &["steering_policy"]),
            ("resource_name", &["name", "id"]),
            ("observed_at", &["modified_on", "created_on"]),
        ],
        CloudflareFamily::LoadBalancerPool => &[
            ("pool_id", &["id"]),
            ("name", &["name"]),
            ("enabled", &["enabled"]),
            ("origins", &["origins"]),
            ("check_regions", &["check_regions"]),
            ("minimum_origins", &["minimum_origins"]),
            ("resource_name", &["name", "id"]),
            ("observed_at", &["modified_on", "created_on"]),
        ],
    }
}

pub(super) fn reject_credential_material(
    value: &Value,
    depth: usize,
) -> Result<(), CloudflareError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(CloudflareError::BudgetExceeded);
    }
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let key = key.to_ascii_lowercase();
                if matches!(
                    key.as_str(),
                    "authorization"
                        | "token"
                        | "password"
                        | "secret"
                        | "api_token"
                        | "access_token"
                        | "refresh_token"
                        | "client_secret"
                        | "session_cookie"
                ) {
                    return Err(CloudflareError::CredentialMaterial);
                }
                reject_credential_material(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_credential_material(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn tenant_event_id(tenant: &str, family: CloudflareFamily, provider_id: &str) -> String {
    let mut hasher = Sha256::new();
    for value in [
        tenant.as_bytes(),
        family.as_str().as_bytes(),
        provider_id.as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    let digest = hasher.finalize();
    format!("cloudflare-{}-{}", family.as_str(), hex(&digest[..12]))
}

pub(super) fn kernel_fingerprint(
    base_url: &str,
    tenant: &str,
    family: CloudflareFamily,
    scope_id: Option<&str>,
    page_size: usize,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let page_size = page_size.to_string();
    for value in [
        base_url,
        tenant,
        family.as_str(),
        scope_id.unwrap_or_default(),
        &page_size,
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.finalize().into()
}

fn hex(value: &[u8]) -> String {
    use std::fmt::Write as _;
    value
        .iter()
        .fold(String::with_capacity(value.len() * 2), |mut out, byte| {
            write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
            out
        })
}
