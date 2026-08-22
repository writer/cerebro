//! Azure Microsoft Graph policy request and response kernels.
//!
//! The kernels implement portable Microsoft Graph contracts for the singleton
//! authentication methods and authorization policies. They plan credential-free
//! requests and decode provider responses without owning credentials, egress policy,
//! deployment routes, or tenant authorization.

use std::{collections::BTreeMap, error::Error, fmt, net::IpAddr, str::FromStr};

use reqwest::Url;
use serde_json::Value;

#[path = "azure/authorization_policy.rs"]
mod authorization_policy;
#[cfg(test)]
#[path = "azure/authorization_policy_tests.rs"]
mod authorization_policy_tests;

const AUTHENTICATION_METHODS_POLICY_PATH: &str = "/v1.0/policies/authenticationMethodsPolicy";
const FAMILY: &str = "authentication_methods_policy";
const PROVIDER_KIND: &str = "azure.authentication_methods_policy";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AzurePolicyFamily {
    AuthenticationMethods,
    Authorization,
}

/// One credential-free Microsoft Graph policy request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureAuthenticationMethodsPolicyRequest {
    url: Url,
    family: AzurePolicyFamily,
}

impl AzureAuthenticationMethodsPolicyRequest {
    /// Return the exact provider URL. The caller must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the required `Authorization` scheme without credential material.
    pub const fn authorization_scheme(&self) -> &'static str {
        "Bearer"
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }
}

/// One normalized Azure Microsoft Graph policy record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureAuthenticationMethodsPolicyRecord {
    /// Source-catalog family identifier.
    pub family: String,
    /// Emitted provider kind.
    pub provider_kind: String,
    /// Stable provider-owned identity, with the family identifier as the singleton fallback.
    pub provider_id: String,
    /// Portable scalar fields used by source mapping.
    pub fields: BTreeMap<String, String>,
    /// Original Microsoft Graph object, with no credentials or tenant metadata added.
    pub payload: Value,
}

/// One complete, non-paginated Azure Microsoft Graph policy response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureAuthenticationMethodsPolicyPage {
    /// The singleton provider record.
    pub records: Vec<AzureAuthenticationMethodsPolicyRecord>,
    /// Microsoft Graph exposes no cursor for this singleton endpoint.
    pub next_cursor: Option<String>,
}

/// Portable request and response kernel for Azure Microsoft Graph policies.
#[derive(Clone, Debug)]
pub struct AzureAuthenticationMethodsPolicyKernel {
    graph_base_url: Url,
}

impl AzureAuthenticationMethodsPolicyKernel {
    /// Build a kernel for one Microsoft Graph origin.
    ///
    /// Planned requests still require the shared live-egress decision and an
    /// operation-scoped credential lease. This type never accepts or stores a
    /// credential value.
    pub fn new(graph_base_url: &str) -> Result<Self, AzureAuthenticationMethodsPolicyError> {
        Ok(Self {
            graph_base_url: validate_origin(graph_base_url)?,
        })
    }

    /// Plan the singleton Microsoft Graph policy request.
    pub fn plan(
        &self,
    ) -> Result<AzureAuthenticationMethodsPolicyRequest, AzureAuthenticationMethodsPolicyError>
    {
        let url = self
            .graph_base_url
            .join(AUTHENTICATION_METHODS_POLICY_PATH)
            .map_err(|_| AzureAuthenticationMethodsPolicyError::InvalidBaseUrl)?;
        Ok(AzureAuthenticationMethodsPolicyRequest {
            url,
            family: AzurePolicyFamily::AuthenticationMethods,
        })
    }

    /// Decode one response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &AzureAuthenticationMethodsPolicyRequest,
        body: &[u8],
    ) -> Result<AzureAuthenticationMethodsPolicyPage, AzureAuthenticationMethodsPolicyError> {
        self.validate_request(request)?;
        let payload: Value = serde_json::from_slice(body)
            .map_err(|_| AzureAuthenticationMethodsPolicyError::InvalidResponse)?;
        if !payload.is_object() {
            return Err(AzureAuthenticationMethodsPolicyError::InvalidResponse);
        }
        let provider_id = nonblank_string(payload.get("id")).unwrap_or_else(|| FAMILY.to_owned());
        let fields = normalize_fields(&payload, &provider_id);
        Ok(AzureAuthenticationMethodsPolicyPage {
            records: vec![AzureAuthenticationMethodsPolicyRecord {
                family: FAMILY.to_owned(),
                provider_kind: PROVIDER_KIND.to_owned(),
                provider_id,
                fields,
                payload,
            }],
            next_cursor: None,
        })
    }

    fn validate_request(
        &self,
        request: &AzureAuthenticationMethodsPolicyRequest,
    ) -> Result<(), AzureAuthenticationMethodsPolicyError> {
        if request.family != AzurePolicyFamily::AuthenticationMethods
            || request.url.origin() != self.graph_base_url.origin()
            || request.url.path() != AUTHENTICATION_METHODS_POLICY_PATH
            || request.url.query().is_some()
            || request.url.fragment().is_some()
        {
            return Err(AzureAuthenticationMethodsPolicyError::RequestScopeMismatch);
        }
        Ok(())
    }
}

/// Stable Azure Graph policy kernel failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AzureAuthenticationMethodsPolicyError {
    /// The configured Microsoft Graph base URL is not an allowed secure origin.
    InvalidBaseUrl,
    /// Response JSON is not a Microsoft Graph singleton object.
    InvalidResponse,
    /// A response request does not match the kernel's origin and exact endpoint.
    RequestScopeMismatch,
    /// Authorization policy response JSON is not a valid Microsoft Graph singleton object.
    AuthorizationPolicyInvalidResponse,
    /// An authorization policy response request does not match the exact endpoint and origin.
    AuthorizationPolicyRequestScopeMismatch,
}

impl fmt::Display for AzureAuthenticationMethodsPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBaseUrl => "azure graph base URL must be a secure origin",
            Self::InvalidResponse => {
                "azure authentication methods policy response must be a JSON object"
            }
            Self::RequestScopeMismatch => {
                "azure authentication methods policy request does not match the kernel"
            }
            Self::AuthorizationPolicyInvalidResponse => {
                "azure authorization policy response must be a JSON object"
            }
            Self::AuthorizationPolicyRequestScopeMismatch => {
                "azure authorization policy request does not match the kernel"
            }
        })
    }
}

impl Error for AzureAuthenticationMethodsPolicyError {}

fn normalize_fields(payload: &Value, provider_id: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    insert_field(
        &mut fields,
        "method_ids",
        array_field_values(payload, &["authenticationMethodConfigurations"], "id"),
    );
    insert_field(
        &mut fields,
        "method_states",
        array_field_values(payload, &["authenticationMethodConfigurations"], "state"),
    );
    insert_field(&mut fields, "policy_id", provider_id.to_owned());
    insert_field(
        &mut fields,
        "policy_name",
        nonblank_string(payload.get("displayName"))
            .unwrap_or_else(|| "Authentication methods policy".to_owned()),
    );
    insert_field(
        &mut fields,
        "policy_status",
        scalar_string(payload.get("policyVersion")),
    );
    insert_field(
        &mut fields,
        "policy_type",
        "authentication_methods".to_owned(),
    );
    insert_field(
        &mut fields,
        "registration_campaign_state",
        scalar_at(
            payload,
            &[
                "registrationEnforcement",
                "authenticationMethodsRegistrationCampaign",
                "state",
            ],
        ),
    );
    insert_field(
        &mut fields,
        "registration_campaign_snooze_days",
        scalar_at(
            payload,
            &[
                "registrationEnforcement",
                "authenticationMethodsRegistrationCampaign",
                "snoozeDurationInDays",
            ],
        ),
    );
    insert_field(
        &mut fields,
        "report_suspicious_activity_state",
        scalar_at(payload, &["reportSuspiciousActivitySettings", "state"]),
    );
    insert_field(
        &mut fields,
        "system_credential_preferences_state",
        scalar_at(payload, &["systemCredentialPreferences", "state"]),
    );
    insert_field(
        &mut fields,
        "system_credential_preferences_exclude_ids",
        array_field_values(
            payload,
            &["systemCredentialPreferences", "excludeTargets"],
            "id",
        ),
    );
    fields
}

fn insert_field(fields: &mut BTreeMap<String, String>, name: &str, value: String) {
    let value = value.trim();
    if !value.is_empty() {
        fields.insert(name.to_owned(), value.to_owned());
    }
}

fn array_field_values(payload: &Value, path: &[&str], field: &str) -> String {
    value_at_path(payload, path)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| nonblank_string(value.get(field)))
        .collect::<Vec<_>>()
        .join(",")
}

fn scalar_at(payload: &Value, path: &[&str]) -> String {
    scalar_string(value_at_path(payload, path))
}

fn value_at_path<'a>(payload: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(payload, |value, segment| value.as_object()?.get(*segment))
}

fn nonblank_string(value: Option<&Value>) -> Option<String> {
    let value = scalar_string(value);
    (!value.trim().is_empty()).then_some(value.trim().to_owned())
}

fn scalar_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn validate_origin(raw: &str) -> Result<Url, AzureAuthenticationMethodsPolicyError> {
    let mut url = Url::parse(raw.trim())
        .map_err(|_| AzureAuthenticationMethodsPolicyError::InvalidBaseUrl)?;
    let host = url
        .host_str()
        .ok_or(AzureAuthenticationMethodsPolicyError::InvalidBaseUrl)?;
    let loopback =
        host == "localhost" || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(AzureAuthenticationMethodsPolicyError::InvalidBaseUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(AzureAuthenticationMethodsPolicyError::InvalidBaseUrl);
    }
    if IpAddr::from_str(host).is_ok_and(|address| unsafe_ip_literal(address, loopback)) {
        return Err(AzureAuthenticationMethodsPolicyError::InvalidBaseUrl);
    }
    if url.port().is_some_and(|port| port != 443) && !loopback {
        return Err(AzureAuthenticationMethodsPolicyError::InvalidBaseUrl);
    }
    url.set_path("/");
    Ok(url)
}

fn unsafe_ip_literal(address: IpAddr, loopback: bool) -> bool {
    if loopback {
        return false;
    }
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
        }
        IpAddr::V6(address) => {
            address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_unspecified()
                || address.is_multicast()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISCOVER_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/azure/testdata/discover_authentication_methods_policy.json"
    ));
    const READ_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sources/azure/testdata/read_authentication_methods_policy.json"
    ));
    const PROVIDER_RESPONSE: &[u8] = br#"{
        "displayName":"Authentication methods policy",
        "policyVersion":"1.5",
        "authenticationMethodConfigurations":[
            {"id":"microsoftAuthenticator","state":"enabled"}
        ],
        "registrationEnforcement":{
            "authenticationMethodsRegistrationCampaign":{
                "state":"enabled",
                "snoozeDurationInDays":3
            }
        },
        "systemCredentialPreferences":{
            "state":"enabled",
            "excludeTargets":[{"id":"break-glass"}]
        },
        "reportSuspiciousActivitySettings":{"state":"enabled"}
    }"#;
    fn kernel() -> AzureAuthenticationMethodsPolicyKernel {
        AzureAuthenticationMethodsPolicyKernel::new("https://graph.microsoft.com").unwrap()
    }

    #[test]
    fn plans_exact_singleton_path_and_credential_free_auth_contract() {
        let request = kernel().plan().unwrap();
        assert_eq!(
            request.url().as_str(),
            "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
        );
        assert_eq!(request.authorization_scheme(), "Bearer");
        assert_eq!(request.accept(), "application/json");
    }

    #[test]
    fn checked_in_fixtures_bind_singleton_identity_kind_and_fields() {
        let kernel = kernel();
        let request = kernel.plan().unwrap();
        let page = kernel.decode(&request, PROVIDER_RESPONSE).unwrap();
        assert_eq!(page.next_cursor, None);
        assert_eq!(page.records.len(), 1);
        let record = &page.records[0];

        let discover: Vec<String> = serde_json::from_slice(DISCOVER_FIXTURE).unwrap();
        assert_eq!(
            discover,
            vec![format!(
                "urn:cerebro:tenant-1:azure_authentication_methods_policy:{}",
                record.provider_id
            )]
        );

        let expected: Value = serde_json::from_slice(READ_FIXTURE).unwrap();
        let expected_event = expected.as_array().unwrap().first().unwrap();
        assert_eq!(
            record.provider_kind,
            expected_event.get("kind").unwrap().as_str().unwrap()
        );
        for name in [
            "family",
            "method_ids",
            "policy_id",
            "policy_name",
            "policy_type",
            "registration_campaign_state",
            "resource_id",
        ] {
            let expected_value = expected_event
                .get("attributes")
                .and_then(|attributes| attributes.get(name))
                .and_then(Value::as_str)
                .unwrap();
            let actual_value = match name {
                "family" => record.family.as_str(),
                "resource_id" => record.provider_id.as_str(),
                _ => record.fields.get(name).map(String::as_str).unwrap(),
            };
            assert_eq!(actual_value, expected_value, "field {name}");
        }
    }

    #[test]
    fn decodes_provider_policy_fields_without_losing_the_raw_object() {
        let kernel = kernel();
        let request = kernel.plan().unwrap();
        let page = kernel.decode(&request, PROVIDER_RESPONSE).unwrap();
        let record = &page.records[0];
        assert_eq!(record.provider_id, FAMILY);
        assert_eq!(
            record.fields.get("method_states").map(String::as_str),
            Some("enabled")
        );
        assert_eq!(
            record
                .fields
                .get("registration_campaign_snooze_days")
                .map(String::as_str),
            Some("3")
        );
        assert_eq!(
            record
                .fields
                .get("system_credential_preferences_exclude_ids")
                .map(String::as_str),
            Some("break-glass")
        );
        assert_eq!(
            record.payload.get("policyVersion").and_then(Value::as_str),
            Some("1.5")
        );
    }

    #[test]
    fn preserves_provider_identity_when_graph_returns_it() {
        let kernel = kernel();
        let request = kernel.plan().unwrap();
        let page = kernel
            .decode(
                &request,
                br#"{"id":"authenticationMethodsPolicy","displayName":"Policy"}"#,
            )
            .unwrap();
        assert_eq!(page.records[0].provider_id, "authenticationMethodsPolicy");
        assert_eq!(
            page.records[0]
                .fields
                .get("policy_name")
                .map(String::as_str),
            Some("Policy")
        );
    }

    #[test]
    fn rejects_non_object_responses_and_cross_origin_requests() {
        let kernel = kernel();
        let request = kernel.plan().unwrap();
        assert_eq!(
            kernel.decode(&request, br#"[]"#),
            Err(AzureAuthenticationMethodsPolicyError::InvalidResponse)
        );

        let other = AzureAuthenticationMethodsPolicyKernel::new("https://graph.example.test")
            .unwrap()
            .plan()
            .unwrap();
        assert_eq!(
            kernel.decode(&other, PROVIDER_RESPONSE),
            Err(AzureAuthenticationMethodsPolicyError::RequestScopeMismatch)
        );
    }

    #[test]
    fn rejects_unsafe_or_non_origin_base_urls() {
        for value in [
            "http://graph.microsoft.com",
            "https://user@graph.microsoft.com",
            "https://graph.microsoft.com/v1.0",
            "https://10.0.0.1",
            "https://graph.microsoft.com?tenant=one",
        ] {
            assert_eq!(
                AzureAuthenticationMethodsPolicyKernel::new(value).unwrap_err(),
                AzureAuthenticationMethodsPolicyError::InvalidBaseUrl,
                "base URL {value}"
            );
        }
    }
}
