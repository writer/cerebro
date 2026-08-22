//! Shared deterministic Kubernetes normalization primitives.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::kubernetes::{
    KubernetesError, KubernetesFamily, KubernetesKernel, KubernetesRecord, request::first_nonempty,
};

pub(super) struct RecordParts {
    pub(super) family: KubernetesFamily,
    pub(super) provider_id: String,
    pub(super) event_id: String,
    pub(super) canonical_urn: String,
    pub(super) attributes: BTreeMap<String, String>,
    pub(super) payload: Value,
    pub(super) occurred_at: String,
}

pub(super) fn build_record(
    kernel: &KubernetesKernel,
    parts: RecordParts,
) -> Result<KubernetesRecord, KubernetesError> {
    let RecordParts {
        family,
        provider_id,
        event_id,
        canonical_urn,
        mut attributes,
        payload,
        occurred_at,
    } = parts;
    if provider_id.trim().is_empty() {
        return Err(KubernetesError::MissingStableIdentity);
    }
    attributes.retain(|key, value| !key.trim().is_empty() && !value.trim().is_empty());
    if canonical_urn.len() > 2_048 || event_id.len() > 512 {
        return Err(KubernetesError::InvalidCanonicalIdentity);
    }
    attributes.insert("family".to_owned(), family.as_str().to_owned());
    attributes.insert("tenant_id".to_owned(), kernel.tenant_id.clone());
    Ok(KubernetesRecord {
        family,
        provider_id,
        event_id,
        canonical_urn,
        event_kind: family.event_kind().to_owned(),
        schema_ref: family.schema_ref().to_owned(),
        attributes,
        payload,
        occurred_at,
    })
}

pub(super) fn base_attributes(
    kernel: &KubernetesKernel,
    resource_type: &str,
    resource_id: &str,
    resource_name: &str,
    namespace: &str,
) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::from([
        ("cluster_id".to_owned(), kernel.cluster_id.clone()),
        ("cluster_name".to_owned(), kernel.cluster_name.clone()),
        ("resource_id".to_owned(), resource_id.to_owned()),
        ("resource_name".to_owned(), resource_name.to_owned()),
        ("resource_type".to_owned(), resource_type.to_owned()),
    ]);
    for (key, value) in [
        ("namespace", namespace),
        ("external_id", &kernel.external_id),
        ("cloud_provider", &kernel.cloud_provider),
        ("cloud_account_id", &kernel.cloud_account_id),
    ] {
        insert_nonempty(&mut attributes, key, value);
    }
    attributes
}

pub(super) fn canonical_urn(
    tenant: &str,
    kind: &str,
    segments: &[&str],
) -> Result<String, KubernetesError> {
    let mut values = Vec::with_capacity(segments.len());
    for value in segments {
        let value = value.trim();
        if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(KubernetesError::InvalidCanonicalIdentity);
        }
        values.push(percent_encode(value));
    }
    Ok(format!(
        "urn:cerebro:{}:{kind}:{}",
        percent_encode(tenant),
        values.join(":")
    ))
}

pub(super) fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[(byte >> 4) as usize]));
            output.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    output
}

pub(super) fn required<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, KubernetesError> {
    let value = string(object, field);
    (!value.is_empty())
        .then_some(value)
        .ok_or(KubernetesError::MissingStableIdentity)
}

pub(super) fn string<'a>(object: &'a Map<String, Value>, field: &str) -> &'a str {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

pub(super) fn pointer_string<'a>(object: &'a Map<String, Value>, pointer: &str) -> &'a str {
    json_pointer(object, pointer)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

pub(super) fn pointer_bool(object: &Map<String, Value>, pointer: &str) -> bool {
    json_pointer(object, pointer)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(super) fn json_pointer<'a>(object: &'a Map<String, Value>, pointer: &str) -> Option<&'a Value> {
    let mut parts = pointer.split('/');
    if parts.next() != Some("") {
        return None;
    }
    let first = parts.next()?;
    let mut value = object.get(first)?;
    for part in parts {
        let part = part.replace("~1", "/").replace("~0", "~");
        value = match value {
            Value::Object(map) => map.get(&part)?,
            Value::Array(items) => items.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(value)
}

pub(super) fn bool_field(object: &Map<String, Value>, field: &str) -> bool {
    object.get(field).and_then(Value::as_bool).unwrap_or(false)
}

pub(super) fn optional_value(object: &Map<String, Value>, field: &str) -> Value {
    object.get(field).cloned().unwrap_or(Value::Null)
}

pub(super) fn optional_string(value: &str) -> Value {
    if value.is_empty() {
        Value::Null
    } else {
        Value::String(value.to_owned())
    }
}

pub(super) fn insert_nonempty(attributes: &mut BTreeMap<String, String>, key: &str, value: &str) {
    let value = value.trim();
    if !value.is_empty() {
        attributes.insert(key.to_owned(), value.to_owned());
    }
}

pub(super) fn insert_json(
    attributes: &mut BTreeMap<String, String>,
    key: &str,
    value: Option<&Value>,
) {
    let Some(value) = value else {
        return;
    };
    if !value.is_null()
        && let Ok(encoded) = serde_json::to_string(value)
    {
        attributes.insert(key.to_owned(), encoded);
    }
}

pub(super) fn array_or_empty(value: Option<&Value>) -> Vec<Value> {
    value.and_then(Value::as_array).cloned().unwrap_or_default()
}

pub(super) fn string_array(value: Option<&Value>) -> Vec<String> {
    let mut values = value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

pub(super) fn object_strings(values: &[Value], field: &str) -> Vec<String> {
    let mut result = values
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|object| object.get(field))
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    result.sort();
    result.dedup();
    result
}

pub(super) fn nested_string_arrays(values: &[Value], field: &str) -> Vec<String> {
    let mut result = values
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|object| object.get(field))
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    result.sort();
    result.dedup();
    result
}

pub(super) fn annotations(metadata: &Map<String, Value>) -> BTreeMap<String, String> {
    metadata
        .get("annotations")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| {
            if !matches!(
                key.as_str(),
                "eks.amazonaws.com/role-arn" | "iam.gke.io/gcp-service-account"
            ) {
                return None;
            }
            value
                .as_str()
                .map(|value| (key.clone(), value.trim().to_owned()))
        })
        .filter(|(_, value)| !value.is_empty())
        .collect()
}

pub(super) fn node_ready(object: &Map<String, Value>) -> bool {
    json_pointer(object, "/status/conditions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .any(|condition| {
            string(condition, "type") == "Ready" && string(condition, "status") == "True"
        })
}

pub(super) fn node_address<'a>(object: &'a Map<String, Value>, kind: &str) -> &'a str {
    json_pointer(object, "/status/addresses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .find(|address| string(address, "type") == kind)
        .map(|address| string(address, "address"))
        .unwrap_or("")
}

pub(super) fn named_objects(value: Option<&Value>) -> BTreeMap<&str, &Map<String, Value>> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(|object| {
            let name = string(object, "name");
            (!name.is_empty()).then_some((name, object))
        })
        .collect()
}

pub(super) fn container_images(object: &Map<String, Value>) -> Vec<String> {
    let mut images = json_pointer(object, "/spec/containers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .map(|container| string(container, "image"))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    images.shrink_to_fit();
    images
}

pub(super) fn container_image_digests(object: &Map<String, Value>) -> Vec<String> {
    let mut digests = json_pointer(object, "/status/containerStatuses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .map(|status| image_digest(string(status, "imageID")))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    digests.sort();
    digests
}

pub(super) fn image_digest(value: &str) -> &str {
    value
        .rfind("@sha256:")
        .map(|index| &value[index + 1..])
        .or_else(|| value.rfind("sha256:").map(|index| &value[index..]))
        .unwrap_or("")
}

pub(super) fn container_state(object: &Map<String, Value>) -> &'static str {
    let Some(state) = object.get("state").and_then(Value::as_object) else {
        return "";
    };
    for key in ["running", "waiting", "terminated"] {
        if state.get(key).is_some_and(|value| !value.is_null()) {
            return key;
        }
    }
    ""
}

pub(super) fn load_balancer_values(object: &Map<String, Value>, field: &str) -> Vec<String> {
    let values = array_or_empty(json_pointer(object, "/status/loadBalancer/ingress"));
    object_strings(&values, field)
}

pub(super) fn service_ports(object: &Map<String, Value>) -> Vec<Value> {
    let mut ports = json_pointer(object, "/spec/ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .map(|port| {
            let mut value = BTreeMap::from([
                ("name".to_owned(), scalar_string(port.get("name"))),
                ("protocol".to_owned(), scalar_string(port.get("protocol"))),
                ("port".to_owned(), scalar_string(port.get("port"))),
                (
                    "target_port".to_owned(),
                    scalar_string(port.get("targetPort")),
                ),
            ]);
            let node_port = scalar_string(port.get("nodePort"));
            if !matches!(node_port.as_str(), "" | "0") {
                value.insert("node_port".to_owned(), node_port);
            }
            serde_json::to_value(value).unwrap_or(Value::Null)
        })
        .collect::<Vec<_>>();
    ports.sort_by_key(|value| {
        format!(
            "{}:{}",
            value.get("port").and_then(Value::as_str).unwrap_or(""),
            value.get("name").and_then(Value::as_str).unwrap_or("")
        )
    });
    ports
}

fn scalar_string(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| value.and_then(Value::as_i64).map(|value| value.to_string()))
        .unwrap_or_else(|| "0".to_owned())
}

pub(super) fn ingress_hosts(rules: &[Value]) -> Vec<String> {
    object_strings(rules, "host")
}

pub(super) fn ingress_backends(object: &Map<String, Value>) -> Vec<String> {
    let mut values = BTreeSet::new();
    if let Some(service) =
        json_pointer(object, "/spec/defaultBackend/service").and_then(Value::as_object)
        && let Some(value) = ingress_service(service)
    {
        values.insert(value);
    }
    for rule in json_pointer(object, "/spec/rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for path in rule
            .pointer("/http/paths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(service) = path.pointer("/backend/service").and_then(Value::as_object)
                && let Some(value) = ingress_service(service)
            {
                values.insert(value);
            }
        }
    }
    values.into_iter().collect()
}

pub(super) fn ingress_service(service: &Map<String, Value>) -> Option<String> {
    let name = string(service, "name");
    if name.is_empty() {
        return None;
    }
    let port = json_pointer(service, "/port/name")
        .and_then(Value::as_str)
        .or_else(|| {
            json_pointer(service, "/port/number")
                .and_then(Value::as_i64)
                .map(|_| "")
        });
    let port = if let Some(port) = port.filter(|value| !value.is_empty()) {
        port.to_owned()
    } else {
        json_pointer(service, "/port/number")
            .and_then(Value::as_i64)
            .map(|value| value.to_string())
            .unwrap_or_default()
    };
    Some(if port.is_empty() {
        name.to_owned()
    } else {
        format!("{name}:{port}")
    })
}

pub(super) fn ingress_rule_summaries(rules: &[Value]) -> Vec<Value> {
    let mut values = BTreeSet::new();
    for rule in rules {
        let host = rule
            .get("host")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("*");
        for path in rule
            .pointer("/http/paths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let path_value = path.get("path").and_then(Value::as_str).unwrap_or("");
            if let Some(service) = path.pointer("/backend/service").and_then(Value::as_object)
                && let Some(service) = ingress_service(service)
            {
                values.insert(format!("{host}:{path_value}->{service}"));
            }
        }
    }
    values.into_iter().map(Value::String).collect()
}

pub(super) fn rbac_rule_summaries(rules: &[Value]) -> Vec<String> {
    let mut values = rules
        .iter()
        .filter_map(Value::as_object)
        .map(|rule| {
            format!(
                "{}:{}:{}",
                string_array(rule.get("apiGroups")).join(","),
                string_array(rule.get("resources")).join(","),
                string_array(rule.get("verbs")).join(",")
            )
        })
        .collect::<Vec<_>>();
    values.sort();
    values
}

pub(super) fn rbac_subject_refs(subjects: &[Value], binding_namespace: &str) -> Vec<Value> {
    let mut refs = subjects
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|subject| {
            let kind = string(subject, "kind");
            let name = string(subject, "name");
            if kind.is_empty() || name.is_empty() {
                return None;
            }
            let namespace = if kind == "ServiceAccount" {
                first_nonempty(&[string(subject, "namespace"), binding_namespace, "default"])
            } else {
                string(subject, "namespace")
            };
            let mut value = Map::from_iter([
                ("kind".to_owned(), Value::String(kind.to_owned())),
                ("name".to_owned(), Value::String(name.to_owned())),
            ]);
            if !namespace.is_empty() {
                value.insert("namespace".to_owned(), Value::String(namespace.to_owned()));
            }
            Some(Value::Object(value))
        })
        .collect::<Vec<_>>();
    refs.sort_by_key(Value::to_string);
    refs
}

pub(super) fn object_time(metadata: &Map<String, Value>, fallback: OffsetDateTime) -> String {
    OffsetDateTime::parse(string(metadata, "creationTimestamp"), &Rfc3339)
        .ok()
        .unwrap_or(fallback)
        .format(&Rfc3339)
        .unwrap_or_else(|_| observed_at_string(fallback))
}

pub(super) fn observed_at_string(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

pub(super) fn bool_string(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

pub(super) fn sha256(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
}
