//! Deterministic Kubernetes provider-object normalization.

mod access;
mod common;
mod core;
mod network;
mod workload;

use serde_json::Value;
use time::OffsetDateTime;

use super::{
    KubernetesError, KubernetesFamily, KubernetesKernel, KubernetesRecord, KubernetesRequest,
};

pub(super) use core::normalize_cluster;

pub(super) fn normalize_object(
    kernel: &KubernetesKernel,
    request: &KubernetesRequest,
    raw: Value,
    observed_at: OffsetDateTime,
) -> Result<Vec<KubernetesRecord>, KubernetesError> {
    let object = raw.as_object().ok_or(KubernetesError::MalformedResponse)?;
    let metadata = object
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or(KubernetesError::MalformedResponse)?;
    match kernel.family {
        KubernetesFamily::Namespace => Ok(vec![core::normalize_namespace(
            kernel,
            object,
            metadata,
            observed_at,
        )?]),
        KubernetesFamily::Node => Ok(vec![core::normalize_node(
            kernel,
            object,
            metadata,
            observed_at,
        )?]),
        KubernetesFamily::Pod | KubernetesFamily::Workload => {
            Ok(vec![workload::normalize_pod_like(
                kernel,
                object,
                metadata,
                observed_at,
            )?])
        }
        KubernetesFamily::Container => {
            workload::normalize_containers(kernel, object, metadata, observed_at)
        }
        KubernetesFamily::Service => Ok(vec![network::normalize_service(
            kernel,
            object,
            metadata,
            observed_at,
        )?]),
        KubernetesFamily::Ingress => Ok(vec![network::normalize_ingress(
            kernel,
            object,
            metadata,
            observed_at,
        )?]),
        KubernetesFamily::ServiceAccount => Ok(vec![access::normalize_service_account(
            kernel,
            object,
            metadata,
            observed_at,
        )?]),
        KubernetesFamily::WorkloadIdentityBinding => {
            access::normalize_workload_identity(kernel, object, metadata, observed_at)
        }
        KubernetesFamily::RbacRole => Ok(vec![access::normalize_rbac_role(
            kernel,
            request,
            object,
            metadata,
            observed_at,
        )?]),
        KubernetesFamily::RbacBinding => Ok(vec![access::normalize_rbac_binding(
            kernel,
            request,
            object,
            metadata,
            observed_at,
        )?]),
        KubernetesFamily::Cluster => Err(KubernetesError::MalformedResponse),
    }
}
