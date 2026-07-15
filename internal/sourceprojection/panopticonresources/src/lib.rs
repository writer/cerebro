#![deny(unsafe_code)]

use serde_json::{Map, Value, json};
use std::collections::HashSet;

pub const ABI_VERSION: u32 = 2;
#[cfg(target_arch = "wasm32")]
const MAX_INPUT_BYTES: usize = 8 << 20;
#[cfg(target_arch = "wasm32")]
const MAX_OUTPUT_BYTES: usize = 8 << 20;
const MAX_RESOURCE_OBJECTS: usize = 128;
const MAX_CONTEXT_DEPTH: usize = 4;

#[cfg(target_arch = "wasm32")]
mod wasm_abi;

const ASSET_OBJECT_KEYS: &[&str] = &["assets", "affected_assets", "hosts", "endpoints"];
const RESOURCE_OBJECT_KEYS: &[&str] = &[
    "resources",
    "affected_resources",
    "affected_resource",
    "impacted_resources",
    "matched_resources",
    "failed_resources",
    "violating_resources",
    "policy_resources",
    "resource_results",
    "target_resources",
    "targets",
    "entities",
    "resource",
    "target",
    "entity",
];
const RESOURCE_CONTEXT_KEYS: &[&str] = &[
    "alert",
    "alerts",
    "linked_alerts",
    "source_alerts",
    "upstream_alerts",
    "related_alerts",
    "alert_context",
    "p_alert_context",
    "panther_alert_context",
    "event",
    "events",
    "finding",
    "findings",
    "log",
    "logs",
    "policy",
    "policy_scan",
    "detail",
    "details",
    "context",
    "metadata",
    "data",
    "result",
    "results",
];

pub fn extract(input: &[u8]) -> Vec<Value> {
    let Ok(Value::Object(payload)) = serde_json::from_slice(input) else {
        return Vec::new();
    };
    let mut objects = Vec::new();
    let mut seen = HashSet::new();
    collect_resource_objects(&mut objects, &mut seen, &payload, 0);
    objects
}

fn collect_resource_objects(
    objects: &mut Vec<Value>,
    seen: &mut HashSet<String>,
    payload: &Map<String, Value>,
    depth: usize,
) {
    if payload.is_empty() || depth > MAX_CONTEXT_DEPTH || objects.len() >= MAX_RESOURCE_OBJECTS {
        return;
    }
    append_objects_for_keys(objects, seen, payload, false, ASSET_OBJECT_KEYS);
    append_objects_for_keys(objects, seen, payload, true, RESOURCE_OBJECT_KEYS);
    for context in objects_for_keys(payload, false, RESOURCE_CONTEXT_KEYS) {
        if looks_like_resource_object(context.as_object()) {
            append_resource_object(objects, seen, context.clone());
        }
        if let Some(context) = context.as_object() {
            collect_resource_objects(objects, seen, context, depth + 1);
        }
        if objects.len() >= MAX_RESOURCE_OBJECTS {
            return;
        }
    }
}

fn append_objects_for_keys(
    objects: &mut Vec<Value>,
    seen: &mut HashSet<String>,
    payload: &Map<String, Value>,
    scalar_as_resource: bool,
    keys: &[&str],
) {
    for object in objects_for_keys(payload, scalar_as_resource, keys) {
        if !scalar_as_resource || looks_like_resource_object(object.as_object()) {
            append_resource_object(objects, seen, object);
        }
        if objects.len() >= MAX_RESOURCE_OBJECTS {
            return;
        }
    }
}

fn append_resource_object(objects: &mut Vec<Value>, seen: &mut HashSet<String>, object: Value) {
    if object.as_object().is_none_or(Map::is_empty) || objects.len() >= MAX_RESOURCE_OBJECTS {
        return;
    }
    let signature = resource_object_signature(object.as_object());
    if !signature.is_empty() && !seen.insert(signature) {
        return;
    }
    objects.push(object);
}

fn resource_object_signature(object: Option<&Map<String, Value>>) -> String {
    let Some(object) = object else {
        return String::new();
    };
    let resource_urn = object_string(object, &["resource_urn"]);
    let resource_arn = first_non_empty(&[
        object_string(object, &["resource_arn"]),
        object_string(object, &["resource_arn", "resourceArn", "arn", "ARN"]),
    ]);
    let resource_id = first_non_empty(&[
        object_string(object, &["resource_id"]),
        object_string(
            object,
            &[
                "resource_id",
                "resourceId",
                "resourceID",
                "ResourceID",
                "resource_arn",
                "resourceArn",
                "arn",
                "ARN",
            ],
        ),
    ]);
    let id = object_string(object, &["id"]);
    let resource_name = first_non_empty(&[
        object_string(object, &["resource_name"]),
        object_string(
            object,
            &[
                "resource_name",
                "resourceName",
                "ResourceName",
                "load_balancer_name",
                "loadBalancerName",
                "name",
                "Name",
                "display_name",
                "displayName",
            ],
        ),
    ]);
    let name = first_non_empty(&[
        object_string(object, &["name"]),
        object_string(object, &["asset_name"]),
        object_string(object, &["device_name"]),
        object_string(object, &["computer_name"]),
        resource_name,
    ]);
    let asset_id = first_non_empty(&[
        object_string(object, &["asset_id"]),
        id.clone(),
        resource_id.clone(),
        resource_arn.clone(),
        resource_urn.clone(),
        name.clone(),
    ]);
    first_non_empty(&[resource_urn, resource_arn, resource_id, asset_id, id, name])
}

fn looks_like_resource_object(object: Option<&Map<String, Value>>) -> bool {
    let Some(object) = object else {
        return false;
    };
    !resource_object_signature(Some(object)).is_empty()
        || !object_string(object, &["hostname"]).is_empty()
}

fn objects_for_keys(
    payload: &Map<String, Value>,
    scalar_as_resource: bool,
    keys: &[&str],
) -> Vec<Value> {
    let wanted: HashSet<String> = keys.iter().map(|key| object_key(key)).collect();
    let mut values = Vec::new();
    let mut seen_payload_keys = HashSet::new();
    for key in keys {
        if let Some(value) = payload.get(*key) {
            seen_payload_keys.insert(*key);
            append_values(&mut values, value, scalar_as_resource);
        }
    }
    for (key, value) in payload {
        if seen_payload_keys.contains(key.as_str()) || !wanted.contains(&object_key(key)) {
            continue;
        }
        append_values(&mut values, value, scalar_as_resource);
    }
    values
}

fn append_values(out: &mut Vec<Value>, value: &Value, scalar_as_resource: bool) {
    match value {
        Value::Array(items) => {
            for item in items {
                if item.is_object() {
                    out.push(item.clone());
                } else if scalar_as_resource && let Some(object) = scalar_resource_object(item) {
                    out.push(object);
                }
            }
        }
        Value::Object(_) => out.push(value.clone()),
        scalar if scalar_as_resource => {
            if let Some(object) = scalar_resource_object(scalar) {
                out.push(object);
            }
        }
        _ => {}
    }
}

fn scalar_resource_object(value: &Value) -> Option<Value> {
    let scalar = scalar_string(value);
    if scalar.is_empty() {
        return None;
    }
    if scalar.starts_with("arn:aws:") {
        Some(json!({"resource_id": scalar, "resource_arn": scalar}))
    } else {
        Some(json!({"resource_id": scalar}))
    }
}

fn object_string(object: &Map<String, Value>, keys: &[&str]) -> String {
    for key in keys {
        if let Some(value) = object.get(*key) {
            let value = scalar_string(value);
            if !value.is_empty() {
                return value;
            }
        }
    }
    let wanted: HashSet<String> = keys.iter().map(|key| object_key(key)).collect();
    for (key, value) in object {
        if wanted.contains(&object_key(key)) {
            let value = scalar_string(value);
            if !value.is_empty() {
                return value;
            }
        }
    }
    String::new()
}

fn object_key(value: &str) -> String {
    value.trim().to_lowercase().replace(['_', '-', '.'], "")
}

fn scalar_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.trim().to_owned(),
        // encoding/json decodes untyped JSON numbers through float64 before the former Go
        // extractor called strconv.FormatFloat(value, 'f', -1, 64). Parsing through f64 and using
        // Rust's shortest fixed-point Display form preserves that behavior, including float64
        // rounding, exponent expansion, and signed zero.
        Value::Number(value) => value
            .as_f64()
            .map(|value| value.to_string())
            .unwrap_or_default(),
        Value::Bool(value) => value.to_string(),
        _ => String::new(),
    }
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(values: &[Value]) -> Vec<String> {
        values
            .iter()
            .filter_map(Value::as_object)
            .map(|object| resource_object_signature(Some(object)))
            .collect()
    }

    #[test]
    fn extracts_direct_nested_and_scalar_resources() {
        let input = br#"{
          "assets":[{"asset_id":"asset-1"}],
          "affectedResources":["arn:aws:s3:::audit"],
          "alerts":[{"resourceResults":[
            {"resourceId":"arn:aws:dynamodb:us-east-1:1:table/events"},
            {"ResourceID":"arn:aws:ec2:us-east-1:1:instance/i-12345678"}
          ]}]
        }"#;
        assert_eq!(
            ids(&extract(input)),
            vec![
                "asset-1",
                "arn:aws:s3:::audit",
                "arn:aws:dynamodb:us-east-1:1:table/events",
                "arn:aws:ec2:us-east-1:1:instance/i-12345678",
            ]
        );
    }

    #[test]
    fn deduplicates_by_first_stable_identifier() {
        let input = br#"{"resources":[
          {"resource_id":"same","name":"first"},
          {"resourceId":"same","name":"second"},
          {"hostname":"host.example"}
        ]}"#;
        let output = extract(input);
        assert_eq!(output.len(), 2);
        assert_eq!(output[0]["name"], "first");
    }

    #[test]
    fn enforces_depth_and_unique_object_caps() {
        let too_deep = br#"{"context":{"context":{"context":{"context":{"context":{"resources":[{"id":"hidden"}]}}}}}}"#;
        assert!(extract(too_deep).is_empty());

        let resources: Vec<Value> = (0..140)
            .map(|index| json!({"resource_id": format!("resource-{index}")}))
            .collect();
        let input = serde_json::to_vec(&json!({"resources": resources})).unwrap();
        assert_eq!(extract(&input).len(), MAX_RESOURCE_OBJECTS);
    }

    #[test]
    fn malformed_or_non_object_payload_is_empty() {
        assert!(extract(b"not-json").is_empty());
        assert!(extract(br#"[1,2,3]"#).is_empty());
        assert!(extract(b"").is_empty());
    }

    #[test]
    fn canonical_keys_precede_normalized_aliases() {
        let input = br#"{
          "resource_results":[{"resource_id":"canonical"}],
          "resourceResults":[{"resource_id":"alias"}]
        }"#;
        assert_eq!(ids(&extract(input)), vec!["canonical", "alias"]);
    }

    #[test]
    fn candidate_conversion_handles_objects_and_scalars() {
        let payload =
            serde_json::from_slice::<Value>(br#"{"resources":["one",{"id":"two"}]}"#).unwrap();
        let values = objects_for_keys(payload.as_object().unwrap(), true, &["resources"]);
        assert_eq!(
            values,
            vec![json!({"resource_id":"one"}), json!({"id":"two"})]
        );
    }

    #[test]
    fn numeric_scalars_match_go_float64_fixed_formatting() {
        let cases = [
            ("1.0", "1"),
            ("9007199254740993", "9007199254740992"),
            ("1e-7", "0.0000001"),
            ("1e20", "100000000000000000000"),
            ("-0.0", "-0"),
        ];
        for (raw, want) in cases {
            let input = format!(r#"{{"resources":[{raw}]}}"#);
            let output = extract(input.as_bytes());
            assert_eq!(output, vec![json!({"resource_id": want})], "input {raw}");
        }
    }

    #[test]
    fn context_objects_with_derived_name_aliases_are_resources() {
        let input = br#"{"alerts":[
          {"assetName":"asset-only"},
          {"deviceName":"device-only"},
          {"computerName":"computer-only"},
          {"resourceName":"resource-only"}
        ]}"#;
        assert_eq!(
            ids(&extract(input)),
            vec![
                "asset-only",
                "device-only",
                "computer-only",
                "resource-only"
            ]
        );
    }
}
