use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRequest {
    #[serde(default)]
    pub(crate) contracts: Vec<CoverageContract>,
    #[serde(default)]
    pub(crate) observations: Vec<RuntimeObservation>,
    #[serde(default)]
    pub(crate) options: Options,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CoverageContract {
    #[serde(default)]
    pub(crate) source_id: String,
    #[serde(default)]
    pub(crate) owner_domain: String,
    #[serde(default)]
    pub(crate) authority_domain: String,
    #[serde(default)]
    pub(crate) dimensions: Vec<CoverageDimension>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CoverageDimension {
    #[serde(default)]
    pub(crate) id: String,
    #[serde(rename = "type", default)]
    pub(crate) dimension_type: String,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) families: Vec<String>,
    #[serde(default)]
    pub(crate) runtime_families: Vec<String>,
    #[serde(default)]
    pub(crate) support: String,
    #[serde(default)]
    pub(crate) high_value: bool,
    #[serde(default)]
    pub(crate) known_unsupported_fields: Vec<String>,
    #[serde(default)]
    pub(crate) notes: Vec<String>,
    #[serde(default)]
    pub(crate) evidence_types: Vec<String>,
    #[serde(default)]
    pub(crate) control_domains: Vec<String>,
    #[serde(default)]
    pub(crate) control_refs: Vec<CoverageControlRef>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub(crate) struct CoverageControlRef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) framework_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) framework_name: String,
    pub(crate) control_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct RuntimeObservation {
    #[serde(default)]
    pub(crate) runtime_id: String,
    #[serde(default)]
    pub(crate) source_id: String,
    #[serde(default)]
    pub(crate) tenant_id: String,
    #[serde(default)]
    pub(crate) family: String,
    #[serde(default)]
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) last_failure_category: String,
    #[serde(default)]
    pub(crate) last_synced_at: String,
    #[serde(default)]
    pub(crate) certification_tier: String,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Options {
    #[serde(default)]
    pub(crate) tenant_id: String,
    #[serde(default)]
    pub(crate) source_id: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Serialize)]
pub(crate) struct EvaluationResponse {
    pub(crate) records: Vec<Record>,
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct Record {
    pub(crate) source_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) tenant_id: String,
    pub(crate) dimension_id: String,
    pub(crate) dimension_type: String,
    pub(crate) title: String,
    pub(crate) state: String,
    pub(crate) support_level: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) runtime_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) last_synced_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) owner_domain: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) authority_domain: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) high_value: bool,
    pub(crate) blind_spot: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) warning: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) known_unsupported_fields: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) notes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) evidence_types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) control_domains: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) control_refs: Vec<CoverageControlRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) supported_runtime_families: Vec<String>,
    pub(crate) certification_tier: String,
}

#[cfg(test)]
mod tests {
    use super::EvaluationRequest;

    #[test]
    fn request_rejects_unknown_top_level_fields() {
        let error = serde_json::from_str::<EvaluationRequest>(r#"{"unexpected":true}"#)
            .expect_err("unknown request fields must fail");
        assert!(error.to_string().contains("unknown field"));
    }
}
