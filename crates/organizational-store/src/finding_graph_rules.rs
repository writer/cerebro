use std::{collections::BTreeMap, sync::OnceLock};

use neo4rs::{BoltList, BoltType, Query, query};
use serde::Deserialize;
use serde_json::Value;

use crate::StoreError;

const CATALOG_JSON: &str = include_str!("finding_graph_rule_catalog.json");

#[derive(Clone, Debug, Deserialize)]
struct CatalogEntry {
    query: String,
    row_limit: usize,
    param_types: BTreeMap<String, String>,
}

static CATALOG: OnceLock<BTreeMap<String, CatalogEntry>> = OnceLock::new();

fn catalog() -> Result<&'static BTreeMap<String, CatalogEntry>, StoreError> {
    if let Some(catalog) = CATALOG.get() {
        return Ok(catalog);
    }
    let parsed = serde_json::from_str(CATALOG_JSON).map_err(StoreError::Serialization)?;
    let _ = CATALOG.set(parsed);
    CATALOG
        .get()
        .ok_or_else(|| StoreError::Conflict("finding graph rule catalog is unavailable".to_owned()))
}

pub(crate) fn rule_query(
    tenant_id: &str,
    rule_id: &str,
    row_limit: usize,
    parameters_json: &[u8],
) -> Result<Query, StoreError> {
    let entry = catalog()?
        .get(rule_id)
        .ok_or_else(|| StoreError::Conflict(format!("unknown finding graph rule {rule_id:?}")))?;
    if row_limit == 0 || row_limit > entry.row_limit || row_limit > 3_000 {
        return Err(StoreError::Conflict(format!(
            "finding graph rule {rule_id:?} row limit must be between 1 and {}",
            entry.row_limit.min(3_000)
        )));
    }
    let supplied: Value = if parameters_json.is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_slice(parameters_json).map_err(StoreError::Serialization)?
    };
    let supplied = supplied.as_object().ok_or_else(|| {
        StoreError::Conflict("finding graph rule parameters must be a JSON object".to_owned())
    })?;
    let expected = entry
        .param_types
        .iter()
        .filter(|(name, _)| name.as_str() != "tenant_id" && name.as_str() != "row_limit")
        .collect::<BTreeMap<_, _>>();
    if supplied.len() != expected.len() || supplied.keys().any(|name| !expected.contains_key(name))
    {
        return Err(StoreError::Conflict(format!(
            "finding graph rule {rule_id:?} parameters do not match the closed catalog"
        )));
    }
    let mut statement = query(&entry.query)
        .param("tenant_id", tenant_id)
        .param("row_limit", i64::try_from(row_limit).unwrap_or(i64::MAX));
    for (name, kind) in expected {
        let value = supplied.get(name).ok_or_else(|| {
            StoreError::Conflict(format!(
                "finding graph rule {rule_id:?} is missing {name:?}"
            ))
        })?;
        statement = match kind.as_str() {
            "string" => statement.param(
                name.as_str(),
                value
                    .as_str()
                    .ok_or_else(|| parameter_type_error(rule_id, name, kind))?,
            ),
            "integer" => statement.param(
                name.as_str(),
                value
                    .as_i64()
                    .ok_or_else(|| parameter_type_error(rule_id, name, kind))?,
            ),
            "boolean" => statement.param(
                name.as_str(),
                value
                    .as_bool()
                    .ok_or_else(|| parameter_type_error(rule_id, name, kind))?,
            ),
            "string_list" => {
                let values = value
                    .as_array()
                    .ok_or_else(|| parameter_type_error(rule_id, name, kind))?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(BoltType::from)
                            .ok_or_else(|| parameter_type_error(rule_id, name, kind))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                statement.param(name.as_str(), BoltType::List(BoltList::from(values)))
            }
            _ => {
                return Err(StoreError::Conflict(format!(
                    "finding graph rule {rule_id:?} has unsupported catalog parameter type {kind:?}"
                )));
            }
        };
    }
    Ok(statement)
}

fn parameter_type_error(rule_id: &str, name: &str, kind: &str) -> StoreError {
    StoreError::Conflict(format!(
        "finding graph rule {rule_id:?} parameter {name:?} must be {kind}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_closed_and_bounded() {
        let entries = catalog().expect("catalog parses");
        assert_eq!(entries.len(), 40);
        assert!(entries.values().all(|entry| {
            !entry.query.trim().is_empty()
                && entry.row_limit > 0
                && entry.row_limit <= 3_000
                && entry.param_types.get("tenant_id").map(String::as_str) == Some("string")
                && entry.param_types.get("row_limit").map(String::as_str) == Some("integer")
        }));
    }

    #[test]
    fn query_rejects_unknown_rule_and_parameter_shape() {
        assert!(rule_query("tenant", "unknown", 1, b"{}").is_err());
        assert!(
            rule_query(
                "tenant",
                "identity-privileged-no-mfa-plus-sensitive-access",
                10,
                br#"{"acted_on_since":false}"#,
            )
            .is_err()
        );
    }
}
