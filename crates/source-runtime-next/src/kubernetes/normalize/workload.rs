//! Pod, workload, and container normalization.

use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use crate::kubernetes::{
    KubernetesError, KubernetesFamily, KubernetesKernel, KubernetesRecord, request::first_nonempty,
};

use super::common::*;

pub(super) fn normalize_pod_like(
    kernel: &KubernetesKernel,
    object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<KubernetesRecord, KubernetesError> {
    let name = required(metadata, "name")?;
    let namespace = required(metadata, "namespace")?;
    let uid = required(metadata, "uid")?;
    let service_account = first_nonempty(&[
        pointer_string(object, "/spec/serviceAccountName"),
        "default",
    ]);
    let images = container_images(object);
    let digests = container_image_digests(object);
    let joined_images = images.join(",");
    let joined_digests = digests.join(",");
    let mut attributes = base_attributes(kernel, "pod", uid, name, namespace);
    for (key, value) in [
        ("uid", uid),
        ("workload_uid", uid),
        ("workload_kind", "Pod"),
        ("workload_name", name),
        ("service_account_name", service_account),
        ("node_name", pointer_string(object, "/spec/nodeName")),
        ("image", joined_images.as_str()),
        ("image_digest", joined_digests.as_str()),
    ] {
        insert_nonempty(&mut attributes, key, value);
    }
    for (key, pointer) in [
        ("host_network", "/spec/hostNetwork"),
        ("host_pid", "/spec/hostPID"),
        ("host_ipc", "/spec/hostIPC"),
    ] {
        attributes.insert(
            key.to_owned(),
            bool_string(pointer_bool(object, pointer)).to_owned(),
        );
    }
    let payload = json!({
        "uid": uid,
        "name": name,
        "namespace": namespace,
        "workload_uid": uid,
        "workload_kind": "Pod",
        "workload_name": name,
        "service_account_name": service_account,
        "node_name": pointer_string(object, "/spec/nodeName"),
        "host_network": pointer_bool(object, "/spec/hostNetwork"),
        "host_pid": pointer_bool(object, "/spec/hostPID"),
        "host_ipc": pointer_bool(object, "/spec/hostIPC"),
        "automount_service_account_token": json_pointer(object, "/spec/automountServiceAccountToken").cloned().unwrap_or(Value::Null),
        "phase": pointer_string(object, "/status/phase"),
        "labels": json_pointer(object, "/metadata/labels").cloned().unwrap_or_else(|| json!({})),
        "images": images,
        "image_digests": digests,
    });
    let canonical_kind = if kernel.family == KubernetesFamily::Pod {
        "kubernetes_pod"
    } else {
        "kubernetes_workload"
    };
    let canonical = canonical_urn(
        &kernel.tenant_id,
        canonical_kind,
        &[&kernel.cluster_id, namespace, uid],
    )?;
    build_record(
        kernel,
        RecordParts {
            family: kernel.family,
            provider_id: uid.to_owned(),
            event_id: format!("kubernetes-pod-{uid}"),
            canonical_urn: canonical,
            attributes,
            payload,
            occurred_at: object_time(metadata, observed_at),
        },
    )
}

pub(super) fn normalize_containers(
    kernel: &KubernetesKernel,
    object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<Vec<KubernetesRecord>, KubernetesError> {
    let pod_name = required(metadata, "name")?;
    let namespace = required(metadata, "namespace")?;
    let pod_uid = required(metadata, "uid")?;
    let containers = json_pointer(object, "/spec/containers")
        .and_then(Value::as_array)
        .ok_or(KubernetesError::MalformedResponse)?;
    let statuses = named_objects(json_pointer(object, "/status/containerStatuses"));
    containers
        .iter()
        .map(|container| {
            let container = container
                .as_object()
                .ok_or(KubernetesError::MalformedResponse)?;
            let name = required(container, "name")?;
            let status = statuses.get(name).copied();
            let mut attributes = base_attributes(kernel, "container", pod_uid, pod_name, namespace);
            for (key, value) in [
                ("uid", pod_uid),
                ("workload_uid", pod_uid),
                ("workload_kind", "Pod"),
                ("workload_name", pod_name),
                ("container_name", name),
                ("image", string(container, "image")),
                ("image_pull_policy", string(container, "imagePullPolicy")),
            ] {
                insert_nonempty(&mut attributes, key, value);
            }
            if let Some(status) = status {
                attributes.insert(
                    "status_ready".to_owned(),
                    bool_string(bool_field(status, "ready")).to_owned(),
                );
                attributes.insert(
                    "status_started".to_owned(),
                    bool_string(bool_field(status, "started")).to_owned(),
                );
                insert_nonempty(&mut attributes, "status_image_id", string(status, "imageID"));
                insert_nonempty(
                    &mut attributes,
                    "image_digest",
                    image_digest(string(status, "imageID")),
                );
                insert_nonempty(&mut attributes, "status_state", container_state(status));
            }
            if let Some(security) = container.get("securityContext").and_then(Value::as_object) {
                for (attribute, field) in [
                    ("allow_privilege_escalation", "allowPrivilegeEscalation"),
                    ("run_as_non_root", "runAsNonRoot"),
                    ("privileged", "privileged"),
                ] {
                    if let Some(value) = security.get(field).and_then(Value::as_bool) {
                        attributes.insert(attribute.to_owned(), bool_string(value).to_owned());
                    }
                }
                if let Some(value) = security.get("runAsUser").and_then(Value::as_i64) {
                    attributes.insert("run_as_user".to_owned(), value.to_string());
                }
            }
            let status_image_id = status.map(|value| string(value, "imageID")).unwrap_or("");
            let payload = json!({
                "pod_uid": pod_uid,
                "pod_name": pod_name,
                "namespace": namespace,
                "container_name": name,
                "image": string(container, "image"),
                "image_pull_policy": string(container, "imagePullPolicy"),
                "status_image_id": status_image_id,
                "image_digest": image_digest(status_image_id),
                "ready": status.map(|value| bool_field(value, "ready")).unwrap_or(false),
                "restart_count": status.and_then(|value| value.get("restartCount")).cloned().unwrap_or(json!(0)),
            });
            let provider_id = format!("{pod_uid}/{name}");
            build_record(
                kernel,
                RecordParts {
                    family: KubernetesFamily::Container,
                    provider_id,
                    event_id: format!(
                        "kubernetes-container-{}",
                        sha256(&format!("{pod_uid}/{name}"))
                    ),
                    canonical_urn: canonical_urn(
                        &kernel.tenant_id,
                        "kubernetes_container",
                        &[&kernel.cluster_id, namespace, pod_uid, name],
                    )?,
                    attributes,
                    payload,
                    occurred_at: object_time(metadata, observed_at),
                },
            )
        })
        .collect()
}
