//! Service and ingress normalization.

use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use crate::kubernetes::{
    KubernetesError, KubernetesFamily, KubernetesKernel, KubernetesRecord, request::first_nonempty,
};

use super::common::*;

pub(super) fn normalize_service(
    kernel: &KubernetesKernel,
    object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<KubernetesRecord, KubernetesError> {
    let name = required(metadata, "name")?;
    let namespace = required(metadata, "namespace")?;
    let uid = first_nonempty(&[string(metadata, "uid"), name]);
    let service_type = pointer_string(object, "/spec/type");
    if service_type.is_empty() {
        return Err(KubernetesError::MissingRequiredPayloadField("type"));
    }
    let ports = service_ports(object);
    let external_ips = string_array(json_pointer(object, "/spec/externalIPs")).join(",");
    let load_balancer_ips = load_balancer_values(object, "ip").join(",");
    let load_balancer_hostnames = load_balancer_values(object, "hostname").join(",");
    let mut attributes = base_attributes(kernel, "service", uid, name, namespace);
    for (key, value) in [
        ("uid", uid),
        ("service_name", name),
        ("service_type", service_type),
        ("cluster_ip", pointer_string(object, "/spec/clusterIP")),
        (
            "external_name",
            pointer_string(object, "/spec/externalName"),
        ),
        ("external_ips", external_ips.as_str()),
        ("load_balancer_ips", load_balancer_ips.as_str()),
        ("load_balancer_hostnames", load_balancer_hostnames.as_str()),
    ] {
        insert_nonempty(&mut attributes, key, value);
    }
    insert_json(&mut attributes, "ports", Some(&Value::Array(ports.clone())));
    insert_json(
        &mut attributes,
        "selector",
        json_pointer(object, "/spec/selector"),
    );
    let payload = json!({
        "uid": uid,
        "name": name,
        "namespace": namespace,
        "type": service_type,
        "cluster_ip": pointer_string(object, "/spec/clusterIP"),
        "cluster_ips": array_or_empty(json_pointer(object, "/spec/clusterIPs")),
        "external_ips": array_or_empty(json_pointer(object, "/spec/externalIPs")),
        "external_name": pointer_string(object, "/spec/externalName"),
        "ip_families": array_or_empty(json_pointer(object, "/spec/ipFamilies")),
        "ports": array_or_empty(json_pointer(object, "/spec/ports")),
        "selector": json_pointer(object, "/spec/selector").cloned().unwrap_or_else(|| json!({})),
        "load_balancer_ingress": array_or_empty(json_pointer(object, "/status/loadBalancer/ingress")),
        "load_balancer_ips": load_balancer_values(object, "ip"),
        "load_balancer_hostnames": load_balancer_values(object, "hostname"),
        "labels": json_pointer(object, "/metadata/labels").cloned().unwrap_or_else(|| json!({})),
        "annotations": json!({}),
    });
    build_record(
        kernel,
        RecordParts {
            family: KubernetesFamily::Service,
            provider_id: uid.to_owned(),
            event_id: format!(
                "kubernetes-service-{}",
                sha256(&format!("{}/{namespace}/{name}", kernel.cluster_id))
            ),
            canonical_urn: canonical_urn(
                &kernel.tenant_id,
                "kubernetes_service",
                &[&kernel.cluster_id, namespace, name],
            )?,
            attributes,
            payload,
            occurred_at: object_time(metadata, observed_at),
        },
    )
}

pub(super) fn normalize_ingress(
    kernel: &KubernetesKernel,
    object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<KubernetesRecord, KubernetesError> {
    let name = required(metadata, "name")?;
    let namespace = required(metadata, "namespace")?;
    let uid = first_nonempty(&[string(metadata, "uid"), name]);
    let rules = array_or_empty(json_pointer(object, "/spec/rules"));
    let hosts = ingress_hosts(&rules);
    let tls = array_or_empty(json_pointer(object, "/spec/tls"));
    let tls_hosts = nested_string_arrays(&tls, "hosts");
    let tls_secrets = object_strings(&tls, "secretName");
    let backends = ingress_backends(object);
    let joined_hosts = hosts.join(",");
    let joined_tls_hosts = tls_hosts.join(",");
    let joined_tls_secrets = tls_secrets.join(",");
    let joined_backends = backends.join(",");
    let load_balancer_ips = load_balancer_values(object, "ip").join(",");
    let load_balancer_hostnames = load_balancer_values(object, "hostname").join(",");
    let mut attributes = base_attributes(kernel, "ingress", uid, name, namespace);
    for (key, value) in [
        ("uid", uid),
        ("ingress_name", name),
        (
            "ingress_class_name",
            pointer_string(object, "/spec/ingressClassName"),
        ),
        ("hosts", joined_hosts.as_str()),
        ("tls_hosts", joined_tls_hosts.as_str()),
        ("tls_secret_names", joined_tls_secrets.as_str()),
        ("backend_services", joined_backends.as_str()),
        ("load_balancer_ips", load_balancer_ips.as_str()),
        ("load_balancer_hostnames", load_balancer_hostnames.as_str()),
    ] {
        insert_nonempty(&mut attributes, key, value);
    }
    insert_json(
        &mut attributes,
        "rules",
        Some(&Value::Array(ingress_rule_summaries(&rules))),
    );
    let payload = json!({
        "uid": uid,
        "name": name,
        "namespace": namespace,
        "ingress_class_name": json_pointer(object, "/spec/ingressClassName").cloned().unwrap_or(Value::Null),
        "rules": rules,
        "tls": tls,
        "default_backend": json_pointer(object, "/spec/defaultBackend").cloned().unwrap_or(Value::Null),
        "load_balancer_ingress": array_or_empty(json_pointer(object, "/status/loadBalancer/ingress")),
        "hosts": hosts,
        "tls_hosts": tls_hosts,
        "backend_services": backends,
        "load_balancer_ips": load_balancer_values(object, "ip"),
        "load_balancer_hostnames": load_balancer_values(object, "hostname"),
        "labels": json_pointer(object, "/metadata/labels").cloned().unwrap_or_else(|| json!({})),
        "annotations": json!({}),
    });
    build_record(
        kernel,
        RecordParts {
            family: KubernetesFamily::Ingress,
            provider_id: uid.to_owned(),
            event_id: format!(
                "kubernetes-ingress-{}",
                sha256(&format!("{}/{namespace}/{name}", kernel.cluster_id))
            ),
            canonical_urn: canonical_urn(
                &kernel.tenant_id,
                "kubernetes_ingress",
                &[&kernel.cluster_id, namespace, name],
            )?,
            attributes,
            payload,
            occurred_at: object_time(metadata, observed_at),
        },
    )
}
