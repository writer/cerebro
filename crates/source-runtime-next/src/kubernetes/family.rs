//! Closed Kubernetes family and event-contract definitions.

use std::str::FromStr;

use super::KubernetesError;

/// Kubernetes inventory and access families preserved from the Go source.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KubernetesFamily {
    /// Kubernetes cluster identity and server version.
    Cluster,
    /// Kubernetes namespaces.
    Namespace,
    /// Kubernetes nodes.
    Node,
    /// Kubernetes pod objects.
    Pod,
    /// Pod-derived workload objects.
    Workload,
    /// Pod container objects.
    Container,
    /// Kubernetes services.
    Service,
    /// Kubernetes ingresses.
    Ingress,
    /// Kubernetes service accounts.
    ServiceAccount,
    /// Kubernetes Role and ClusterRole objects.
    RbacRole,
    /// Kubernetes RoleBinding and ClusterRoleBinding objects.
    RbacBinding,
    /// AWS IRSA and GKE workload-identity bindings derived from service accounts.
    WorkloadIdentityBinding,
}

/// One catalog family compiled into the closed Kubernetes runtime contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KubernetesRuntimeDefinition {
    family: KubernetesFamily,
}

impl KubernetesRuntimeDefinition {
    /// Compile and fail closed on any source, family, event, schema, or field drift.
    pub fn compile(
        source_id: &str,
        family_id: &str,
        event_kind: &str,
        schema_ref: &str,
        required_attributes: &[String],
        required_payload_fields: &[String],
    ) -> Result<Self, KubernetesError> {
        let family = KubernetesFamily::from_str(family_id)?;
        let exact = source_id == "kubernetes"
            && event_kind == family.event_kind()
            && schema_ref == family.schema_ref()
            && strings_equal(required_attributes, family.required_attributes())
            && strings_equal(required_payload_fields, family.required_payload_fields());
        exact
            .then_some(Self { family })
            .ok_or(KubernetesError::InvalidRuntimeDefinition)
    }

    /// Return the closed Kubernetes family.
    pub const fn family(self) -> KubernetesFamily {
        self.family
    }

    /// Return the exact admitted event kind.
    pub const fn event_kind(self) -> &'static str {
        self.family.event_kind()
    }

    /// Return the exact admitted schema reference.
    pub const fn schema_ref(self) -> &'static str {
        self.family.schema_ref()
    }

    /// Return the exact required event attributes.
    pub const fn required_attributes(self) -> &'static [&'static str] {
        self.family.required_attributes()
    }

    /// Return the exact required payload fields.
    pub const fn required_payload_fields(self) -> &'static [&'static str] {
        self.family.required_payload_fields()
    }
}

fn strings_equal(actual: &[String], expected: &[&str]) -> bool {
    actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
}

impl KubernetesFamily {
    /// Return the exact source catalog family identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cluster => "cluster",
            Self::Namespace => "namespace",
            Self::Node => "node",
            Self::Pod => "pod",
            Self::Workload => "workload",
            Self::Container => "container",
            Self::Service => "service",
            Self::Ingress => "ingress",
            Self::ServiceAccount => "service_account",
            Self::RbacRole => "rbac_role",
            Self::RbacBinding => "rbac_binding",
            Self::WorkloadIdentityBinding => "workload_identity_binding",
        }
    }

    /// Return the exact event kind admitted by the source catalog.
    pub const fn event_kind(self) -> &'static str {
        match self {
            Self::Cluster => "kubernetes.cluster",
            Self::Namespace => "kubernetes.namespace",
            Self::Node => "kubernetes.node",
            Self::Pod => "kubernetes.pod",
            Self::Workload => "kubernetes.workload",
            Self::Container => "kubernetes.container",
            Self::Service => "kubernetes.service",
            Self::Ingress => "kubernetes.ingress",
            Self::ServiceAccount => "kubernetes.service_account",
            Self::RbacRole => "kubernetes.rbac_role",
            Self::RbacBinding => "kubernetes.rbac_binding",
            Self::WorkloadIdentityBinding => "kubernetes.workload_identity_binding",
        }
    }

    /// Return the exact schema reference admitted by the source catalog.
    pub const fn schema_ref(self) -> &'static str {
        match self {
            Self::Cluster => "kubernetes/cluster/v1",
            Self::Namespace => "kubernetes/namespace/v1",
            Self::Node => "kubernetes/node/v1",
            Self::Pod => "kubernetes/pod/v1",
            Self::Workload => "kubernetes/workload/v1",
            Self::Container => "kubernetes/container/v1",
            Self::Service => "kubernetes/service/v1",
            Self::Ingress => "kubernetes/ingress/v1",
            Self::ServiceAccount => "kubernetes/service_account/v1",
            Self::RbacRole => "kubernetes/rbac_role/v1",
            Self::RbacBinding => "kubernetes/rbac_binding/v1",
            Self::WorkloadIdentityBinding => "kubernetes/workload_identity_binding/v1",
        }
    }

    pub(super) const fn initial_path(self) -> &'static str {
        match self {
            Self::Cluster => "/version",
            Self::Namespace => "/api/v1/namespaces",
            Self::Node => "/api/v1/nodes",
            Self::Pod | Self::Workload | Self::Container => "/api/v1/pods",
            Self::Service => "/api/v1/services",
            Self::Ingress => "/apis/networking.k8s.io/v1/ingresses",
            Self::ServiceAccount | Self::WorkloadIdentityBinding => "/api/v1/serviceaccounts",
            Self::RbacRole => "/apis/rbac.authorization.k8s.io/v1/roles",
            Self::RbacBinding => "/apis/rbac.authorization.k8s.io/v1/rolebindings",
        }
    }

    pub(super) const fn required_attributes(self) -> &'static [&'static str] {
        match self {
            Self::Cluster => &["cluster_id", "cluster_name"],
            Self::Namespace => &["cluster_id", "namespace"],
            Self::Node => &["cluster_id", "node_name", "ready"],
            Self::Pod | Self::Workload => &["cluster_id", "namespace", "workload_uid"],
            Self::Container => &["cluster_id", "container_name", "namespace"],
            Self::Service => &["cluster_id", "namespace", "service_name", "service_type"],
            Self::Ingress => &["cluster_id", "ingress_name", "namespace"],
            Self::ServiceAccount => &["cluster_id", "namespace", "service_account_name"],
            Self::RbacRole => &["cluster_id", "role_kind", "role_name"],
            Self::RbacBinding => &["binding_kind", "binding_name", "cluster_id", "role_name"],
            Self::WorkloadIdentityBinding => &[
                "cloud_provider",
                "cluster_id",
                "namespace",
                "service_account_name",
                "target_id",
            ],
        }
    }

    pub(super) const fn required_payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::Cluster => &["cluster_id", "cluster_name"],
            Self::Namespace => &["name", "uid"],
            Self::Node => &["name", "node_info", "ready"],
            Self::Pod => &["name", "namespace", "uid"],
            Self::Workload => &["workload_kind", "workload_name", "workload_uid"],
            Self::Container => &["container_name", "pod_uid"],
            Self::Service => &["name", "namespace", "ports", "type"],
            Self::Ingress => &["name", "namespace", "rules"],
            Self::ServiceAccount => &["name", "namespace"],
            Self::RbacRole => &["name", "role_kind", "rules"],
            Self::RbacBinding => &["binding_kind", "name", "role_ref"],
            Self::WorkloadIdentityBinding => {
                &["cloud_provider", "service_account_name", "target_id"]
            }
        }
    }
}

impl FromStr for KubernetesFamily {
    type Err = KubernetesError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "cluster" => Ok(Self::Cluster),
            "namespace" => Ok(Self::Namespace),
            "node" => Ok(Self::Node),
            "pod" => Ok(Self::Pod),
            "workload" => Ok(Self::Workload),
            "container" => Ok(Self::Container),
            "service" => Ok(Self::Service),
            "ingress" => Ok(Self::Ingress),
            "service_account" => Ok(Self::ServiceAccount),
            "rbac_role" => Ok(Self::RbacRole),
            "rbac_binding" => Ok(Self::RbacBinding),
            "workload_identity_binding" => Ok(Self::WorkloadIdentityBinding),
            _ => Err(KubernetesError::InvalidFamily),
        }
    }
}
