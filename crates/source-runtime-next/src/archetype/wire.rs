use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct ScanResponse {
    pub(super) id: u64,
    pub(super) repository_id: u64,
    pub(super) status: String,
    pub(super) started_at: String,
    pub(super) completed_at: String,
    pub(super) created_at: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct RepositoryResponse {
    pub(super) id: u64,
    pub(super) owner: String,
    pub(super) name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct VulnerabilityResponse {
    pub(super) id: u64,
    pub(super) scan_id: u64,
    pub(super) line_number: u64,
    pub(super) file_path: String,
    pub(super) category: String,
    pub(super) severity: String,
    pub(super) description: String,
    pub(super) analyzer_score: f64,
    pub(super) analyzer_label: String,
    pub(super) created_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct KnowledgeEntryResponse {
    pub(super) slug: String,
    pub(super) title: String,
    pub(super) summary: String,
    pub(super) topics: Vec<String>,
    pub(super) generated_at: String,
    pub(super) source_files: Vec<String>,
    pub(super) metadata: BTreeMap<String, Value>,
    pub(super) severity_tags: Vec<String>,
    pub(super) dominant_severity: String,
    pub(super) severity_breakdown: Vec<Value>,
    pub(super) repository_id: u64,
    pub(super) repository_name: String,
    pub(super) owner: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct KnowledgeResponse {
    pub(super) entries: Vec<KnowledgeEntryResponse>,
}
