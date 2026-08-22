//! Credential-free Kubernetes request planning and origin enforcement.

use std::fmt;

use reqwest::Url;

use super::{
    KubernetesError, KubernetesFamily, KubernetesRuntimeDefinition,
    cursor::{RbacStage, bounded_token, decode_rbac_cursor},
};

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 500;
const MAX_RESPONSE_BYTES: usize = 8 << 20;

/// Public, credential-free Kubernetes runtime configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesConfig {
    /// Tenant sealed by the authenticated runtime context.
    pub tenant_id: String,
    /// Exact Kubernetes API server origin selected by the trusted host.
    pub api_server: String,
    /// Stable cluster identity used by the Go source and graph projection.
    pub cluster_id: String,
    /// Operator-facing cluster name.
    pub cluster_name: String,
    /// Optional provider external identity.
    pub external_id: String,
    /// Optional normalized cloud provider.
    pub cloud_provider: String,
    /// Optional cloud account, project, or subscription identity.
    pub cloud_account_id: String,
    /// Provider page size in the inclusive 1 through 500 range.
    pub per_page: usize,
}

impl KubernetesConfig {
    /// Construct the smallest valid public configuration.
    pub fn new(
        tenant_id: impl Into<String>,
        api_server: impl Into<String>,
        cluster_id: impl Into<String>,
        cluster_name: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            api_server: api_server.into(),
            cluster_id: cluster_id.into(),
            cluster_name: cluster_name.into(),
            external_id: String::new(),
            cloud_provider: String::new(),
            cloud_account_id: String::new(),
            per_page: DEFAULT_PAGE_SIZE,
        }
    }
}

/// One origin-locked Kubernetes request plan without credential material.
#[derive(Clone, Eq, PartialEq)]
pub struct KubernetesRequest {
    pub(super) url: Url,
    pub(super) family: KubernetesFamily,
    pub(super) rbac_stage: Option<RbacStage>,
}

impl fmt::Debug for KubernetesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesRequest")
            .field("method", &self.method())
            .field("origin", &self.url.origin().ascii_serialization())
            .field("path", &self.url.path())
            .field("family", &self.family)
            .field("redirects_allowed", &self.allows_redirects())
            .field("max_response_bytes", &self.max_response_bytes())
            .finish()
    }
}

impl KubernetesRequest {
    /// Return the provider method for this read-only operation.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Return the exact provider URL. The trusted host must authorize it before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return the credential-free authentication mode owned by the trusted host.
    pub const fn authentication_mode(&self) -> &'static str {
        "host_managed_kubernetes"
    }

    /// The portable request never contains kubeconfig or resolved credential bytes.
    pub const fn contains_credentials(&self) -> bool {
        false
    }

    /// Redirects are denied so authentication cannot leave the compiled origin.
    pub const fn allows_redirects(&self) -> bool {
        false
    }

    /// Return the required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/json"
    }

    /// Return the response body bound enforced before decoding.
    pub const fn max_response_bytes(&self) -> usize {
        MAX_RESPONSE_BYTES
    }
}

/// Bounded request and normalization kernel for one Kubernetes family.
#[derive(Clone, Debug)]
pub struct KubernetesKernel {
    pub(super) api_server: Url,
    pub(super) tenant_id: String,
    pub(super) cluster_id: String,
    pub(super) cluster_name: String,
    pub(super) external_id: String,
    pub(super) cloud_provider: String,
    pub(super) cloud_account_id: String,
    pub(super) family: KubernetesFamily,
    pub(super) page_size: usize,
}

impl KubernetesKernel {
    /// Construct a kernel from one exact catalog-compiled runtime definition.
    pub fn compile(
        config: KubernetesConfig,
        definition: KubernetesRuntimeDefinition,
    ) -> Result<Self, KubernetesError> {
        Self::new(config, definition.family())
    }

    pub(super) fn new(
        config: KubernetesConfig,
        family: KubernetesFamily,
    ) -> Result<Self, KubernetesError> {
        let tenant_id = required_identity(&config.tenant_id, KubernetesError::MissingTenantId)?;
        let scoped_cluster_id = scoped_cluster_id(&config.cloud_account_id, &config.cluster_name);
        let cluster_id = required_identity(
            first_nonempty(&[
                &config.cluster_id,
                &config.external_id,
                &scoped_cluster_id,
                &config.cluster_name,
            ]),
            KubernetesError::MissingClusterIdentity,
        )?;
        let cluster_name = first_nonempty(&[
            &config.cluster_name,
            &config.external_id,
            &config.cluster_id,
        ]);
        let api_server = validate_origin(&config.api_server)?;
        if !(1..=MAX_PAGE_SIZE).contains(&config.per_page) {
            return Err(KubernetesError::InvalidPageSize);
        }
        Ok(Self {
            api_server,
            tenant_id,
            cluster_id,
            cluster_name: if cluster_name.is_empty() {
                "cluster".to_owned()
            } else {
                cluster_name.to_owned()
            },
            external_id: config.external_id.trim().to_owned(),
            cloud_provider: normalize_identifier(&config.cloud_provider),
            cloud_account_id: config.cloud_account_id.trim().to_owned(),
            family,
            page_size: config.per_page,
        })
    }

    /// This kernel accepts no kubeconfig, token, certificate, or other credential value.
    pub const fn requires_credentials() -> bool {
        false
    }

    /// Plan one bounded provider request using only an opaque prior continuation.
    pub fn plan(&self, cursor: Option<&str>) -> Result<KubernetesRequest, KubernetesError> {
        let (path, token, stage) = match self.family {
            KubernetesFamily::RbacRole | KubernetesFamily::RbacBinding => {
                let cursor = decode_rbac_cursor(self.family, cursor)?;
                let path = match cursor.stage {
                    RbacStage::Role => "/apis/rbac.authorization.k8s.io/v1/roles",
                    RbacStage::ClusterRole => "/apis/rbac.authorization.k8s.io/v1/clusterroles",
                    RbacStage::RoleBinding => "/apis/rbac.authorization.k8s.io/v1/rolebindings",
                    RbacStage::ClusterRoleBinding => {
                        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
                    }
                };
                (
                    path,
                    bounded_token(Some(&cursor.token))?,
                    Some(cursor.stage),
                )
            }
            _ => (self.family.initial_path(), bounded_token(cursor)?, None),
        };
        let mut url = self.api_server.clone();
        url.set_path(path);
        if self.family != KubernetesFamily::Cluster {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &self.page_size.to_string());
            if let Some(token) = token {
                query.append_pair("continue", &token);
            }
        }
        Ok(KubernetesRequest {
            url,
            family: self.family,
            rbac_stage: stage,
        })
    }

    pub(super) fn validate_request(
        &self,
        request: &KubernetesRequest,
    ) -> Result<(), KubernetesError> {
        if request.family != self.family
            || request.url.origin() != self.api_server.origin()
            || request.url.fragment().is_some()
            || request.url.username() != ""
            || request.url.password().is_some()
        {
            return Err(KubernetesError::RequestScopeMismatch);
        }
        let expected_path = match request.rbac_stage {
            Some(RbacStage::Role) => "/apis/rbac.authorization.k8s.io/v1/roles",
            Some(RbacStage::ClusterRole) => "/apis/rbac.authorization.k8s.io/v1/clusterroles",
            Some(RbacStage::RoleBinding) => "/apis/rbac.authorization.k8s.io/v1/rolebindings",
            Some(RbacStage::ClusterRoleBinding) => {
                "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
            }
            None => self.family.initial_path(),
        };
        if request.url.path() != expected_path {
            return Err(KubernetesError::RequestScopeMismatch);
        }
        if self.family == KubernetesFamily::Cluster {
            return request
                .url
                .query()
                .is_none()
                .then_some(())
                .ok_or(KubernetesError::RequestScopeMismatch);
        }
        let mut limit = None;
        let mut continuation = None;
        for (key, value) in request.url.query_pairs() {
            match key.as_ref() {
                "limit" if limit.is_none() => limit = Some(value.into_owned()),
                "continue" if continuation.is_none() => {
                    continuation = Some(value.into_owned());
                }
                _ => return Err(KubernetesError::RequestScopeMismatch),
            }
        }
        let expected_limit = self.page_size.to_string();
        if limit.as_deref() != Some(expected_limit.as_str())
            || bounded_token(continuation.as_deref())? != continuation
        {
            return Err(KubernetesError::RequestScopeMismatch);
        }
        Ok(())
    }
}

fn validate_origin(value: &str) -> Result<Url, KubernetesError> {
    let mut url = Url::parse(value.trim()).map_err(|_| KubernetesError::InvalidApiServer)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(KubernetesError::InvalidApiServer);
    }
    url.set_path("");
    Ok(url)
}

fn required_identity(value: &str, error: KubernetesError) -> Result<String, KubernetesError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(error);
    }
    Ok(value.to_owned())
}

fn scoped_cluster_id(account: &str, cluster: &str) -> String {
    if account.trim().is_empty() || cluster.trim().is_empty() {
        return String::new();
    }
    format!("{}:{}", account.trim(), cluster.trim())
}

pub(super) fn first_nonempty<'a>(values: &[&'a str]) -> &'a str {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or("")
}

fn normalize_identifier(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

pub(super) const fn max_response_bytes() -> usize {
    MAX_RESPONSE_BYTES
}
