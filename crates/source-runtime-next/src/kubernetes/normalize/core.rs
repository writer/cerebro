//! Cluster, namespace, and node normalization.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use crate::kubernetes::{
    KubernetesError, KubernetesFamily, KubernetesKernel, KubernetesRecord, request::first_nonempty,
};

use super::common::*;

pub(in crate::kubernetes) fn normalize_cluster(
    kernel: &KubernetesKernel,
    response: Value,
    observed_at: OffsetDateTime,
) -> Result<KubernetesRecord, KubernetesError> {
    let object = response
        .as_object()
        .ok_or(KubernetesError::MalformedResponse)?;
    let mut attributes = BTreeMap::from([
        ("cluster_id".to_owned(), kernel.cluster_id.clone()),
        ("cluster_name".to_owned(), kernel.cluster_name.clone()),
    ]);
    insert_nonempty(&mut attributes, "external_id", &kernel.external_id);
    insert_nonempty(&mut attributes, "cloud_provider", &kernel.cloud_provider);
    insert_nonempty(
        &mut attributes,
        "cloud_account_id",
        &kernel.cloud_account_id,
    );
    for (attribute, provider) in [
        ("git_version", "gitVersion"),
        ("version_major", "major"),
        ("version_minor", "minor"),
        ("platform", "platform"),
    ] {
        insert_nonempty(&mut attributes, attribute, string(object, provider));
    }
    let payload = json!({
        "cluster_id": kernel.cluster_id,
        "cluster_name": kernel.cluster_name,
        "external_id": optional_string(&kernel.external_id),
        "git_version": optional_value(object, "gitVersion"),
        "major": optional_value(object, "major"),
        "minor": optional_value(object, "minor"),
        "platform": optional_value(object, "platform"),
        "cloud_provider": optional_string(&kernel.cloud_provider),
        "cloud_account_id": optional_string(&kernel.cloud_account_id),
    });
    build_record(
        kernel,
        RecordParts {
            family: KubernetesFamily::Cluster,
            provider_id: kernel.cluster_id.clone(),
            event_id: format!("kubernetes-cluster-{}", kernel.cluster_id),
            canonical_urn: canonical_urn(
                &kernel.tenant_id,
                "kubernetes_cluster",
                &[&kernel.cluster_id],
            )?,
            attributes,
            payload,
            occurred_at: observed_at_string(observed_at),
        },
    )
}

pub(super) fn normalize_namespace(
    kernel: &KubernetesKernel,
    object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<KubernetesRecord, KubernetesError> {
    let name = required(metadata, "name")?;
    let uid = required(metadata, "uid")?;
    let mut attributes = base_attributes(kernel, "namespace", uid, name, name);
    attributes.insert("namespace".to_owned(), name.to_owned());
    let payload = json!({
        "uid": uid,
        "name": name,
        "status": json_pointer(object, "/status/phase").cloned().unwrap_or(Value::String(String::new())),
    });
    build_record(
        kernel,
        RecordParts {
            family: KubernetesFamily::Namespace,
            provider_id: uid.to_owned(),
            event_id: format!("kubernetes-namespace-{uid}"),
            canonical_urn: canonical_urn(
                &kernel.tenant_id,
                "kubernetes_namespace",
                &[&kernel.cluster_id, uid],
            )?,
            attributes,
            payload,
            occurred_at: object_time(metadata, observed_at),
        },
    )
}

pub(super) fn normalize_node(
    kernel: &KubernetesKernel,
    object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<KubernetesRecord, KubernetesError> {
    let name = required(metadata, "name")?;
    let uid = first_nonempty(&[string(metadata, "uid"), name]);
    let ready = node_ready(object);
    let mut attributes = base_attributes(kernel, "node", uid, name, "");
    for (key, value) in [
        ("uid", uid),
        ("node_name", name),
        ("ready", bool_string(ready)),
        ("provider_id", pointer_string(object, "/spec/providerID")),
        ("pod_cidr", pointer_string(object, "/spec/podCIDR")),
        ("internal_ip", node_address(object, "InternalIP")),
        ("external_ip", node_address(object, "ExternalIP")),
        (
            "kernel_version",
            pointer_string(object, "/status/nodeInfo/kernelVersion"),
        ),
        (
            "kubelet_version",
            pointer_string(object, "/status/nodeInfo/kubeletVersion"),
        ),
        (
            "container_runtime_version",
            pointer_string(object, "/status/nodeInfo/containerRuntimeVersion"),
        ),
        (
            "os_image",
            pointer_string(object, "/status/nodeInfo/osImage"),
        ),
        (
            "operating_system",
            pointer_string(object, "/status/nodeInfo/operatingSystem"),
        ),
        (
            "architecture",
            pointer_string(object, "/status/nodeInfo/architecture"),
        ),
    ] {
        insert_nonempty(&mut attributes, key, value);
    }
    attributes.insert(
        "unschedulable".to_owned(),
        bool_string(pointer_bool(object, "/spec/unschedulable")).to_owned(),
    );
    for (key, pointer) in [
        ("pod_cidrs", "/spec/podCIDRs"),
        ("labels", "/metadata/labels"),
        ("taints", "/spec/taints"),
        ("capacity", "/status/capacity"),
        ("allocatable", "/status/allocatable"),
    ] {
        insert_json(&mut attributes, key, json_pointer(object, pointer));
    }
    let payload = json!({
        "uid": uid,
        "name": name,
        "provider_id": json_pointer(object, "/spec/providerID").cloned().unwrap_or(Value::String(String::new())),
        "unschedulable": pointer_bool(object, "/spec/unschedulable"),
        "pod_cidr": json_pointer(object, "/spec/podCIDR").cloned().unwrap_or(Value::String(String::new())),
        "pod_cidrs": array_or_empty(json_pointer(object, "/spec/podCIDRs")),
        "taints": array_or_empty(json_pointer(object, "/spec/taints")),
        "labels": json_pointer(object, "/metadata/labels").cloned().unwrap_or_else(|| json!({})),
        "annotations": json!({}),
        "addresses": array_or_empty(json_pointer(object, "/status/addresses")),
        "conditions": array_or_empty(json_pointer(object, "/status/conditions")),
        "capacity": json_pointer(object, "/status/capacity").cloned().unwrap_or_else(|| json!({})),
        "allocatable": json_pointer(object, "/status/allocatable").cloned().unwrap_or_else(|| json!({})),
        "node_info": json_pointer(object, "/status/nodeInfo").cloned().unwrap_or_else(|| json!({})),
        "ready": ready,
        "internal_ip": node_address(object, "InternalIP"),
        "external_ip": node_address(object, "ExternalIP"),
        "kubelet_version": pointer_string(object, "/status/nodeInfo/kubeletVersion"),
        "container_runtime": pointer_string(object, "/status/nodeInfo/containerRuntimeVersion"),
    });
    build_record(
        kernel,
        RecordParts {
            family: KubernetesFamily::Node,
            provider_id: uid.to_owned(),
            event_id: format!(
                "kubernetes-node-{}",
                sha256(&format!("{}/{name}", kernel.cluster_id))
            ),
            canonical_urn: canonical_urn(
                &kernel.tenant_id,
                "kubernetes_node",
                &[&kernel.cluster_id, name],
            )?,
            attributes,
            payload,
            occurred_at: object_time(metadata, observed_at),
        },
    )
}
