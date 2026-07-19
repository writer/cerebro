use serde_json::{Map, Value, json};
use std::collections::HashSet;

pub(crate) fn resource_object_signature(object: Option<&Map<String, Value>>) -> String {
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

pub(crate) fn scalar_resource_object(value: &Value) -> Option<Value> {
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

pub(crate) fn object_string(object: &Map<String, Value>, keys: &[&str]) -> String {
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

pub(crate) fn object_key(value: &str) -> String {
    value.trim().to_lowercase().replace(['_', '-', '.'], "")
}

fn scalar_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.trim().to_owned(),
        // Match encoding/json's float64 conversion and strconv fixed-point formatting.
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

    #[test]
    fn signature_normalizes_aliases_without_changing_precedence() {
        let object = serde_json::json!({
            "ResourceID": "resource-alias",
            "resource_urn": "urn:canonical"
        });
        assert_eq!(
            resource_object_signature(object.as_object()),
            "urn:canonical"
        );
    }

    #[test]
    fn scalar_resource_preserves_arn_identity() {
        assert_eq!(
            scalar_resource_object(&Value::String("arn:aws:s3:::audit".to_owned())),
            Some(serde_json::json!({
                "resource_id": "arn:aws:s3:::audit",
                "resource_arn": "arn:aws:s3:::audit"
            }))
        );
    }
}
