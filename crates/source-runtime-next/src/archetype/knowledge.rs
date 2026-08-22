//! Repository-knowledge decoding and `archetype.library_note` normalization.

use std::collections::{BTreeMap, HashMap};

use serde_json::Value;

use super::{
    ArchetypeError, ArchetypeKernel, ArchetypeRecord, ArchetypeRepository, ArchetypeRequest,
    ArchetypeRequestKind, ArchetypeScan,
    adapter::{RecordParts, validate_enrichment_count, validate_response_size},
    normalization::{compact, require_repository_scope},
    wire::KnowledgeResponse,
};

impl ArchetypeKernel {
    /// Decode repository knowledge into catalog-valid library-note records.
    pub fn decode_knowledge(
        &self,
        request: &ArchetypeRequest,
        body: &[u8],
        scan: &ArchetypeScan,
        repository: Option<&ArchetypeRepository>,
        observed_at: &str,
    ) -> Result<Vec<ArchetypeRecord>, ArchetypeError> {
        scan.validate_invariant()?;
        self.require_vulnerability_family()?;
        self.validate_request(
            request,
            ArchetypeRequestKind::Knowledge,
            Some(scan.repository_id),
        )?;
        require_repository_scope(scan, repository)?;
        validate_response_size(body)?;
        let response: KnowledgeResponse =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        validate_enrichment_count(response.entries.len())?;
        let mut identities = HashMap::new();
        let mut records = Vec::new();
        for mut entry in response.entries {
            entry.slug = entry.slug.trim().to_owned();
            if entry.repository_id == 0 {
                entry.repository_id = scan.repository_id;
            } else if entry.repository_id != scan.repository_id {
                return Err(ArchetypeError::ResponseScopeMismatch);
            }
            if entry.owner.trim().is_empty() {
                entry.owner = repository
                    .map_or("", |value| value.owner.as_str())
                    .to_owned();
            }
            if entry.repository_name.trim().is_empty() {
                entry.repository_name = repository
                    .map_or("", |value| value.name.as_str())
                    .to_owned();
            }
            entry.owner = entry.owner.trim().to_owned();
            entry.repository_name = entry.repository_name.trim().to_owned();
            if entry.slug.is_empty() || entry.owner.is_empty() || entry.repository_name.is_empty() {
                continue;
            }
            if entry.title.trim().is_empty() || entry.summary.trim().is_empty() {
                return Err(ArchetypeError::InvalidResponse);
            }
            if metadata_contains_secret_field(&entry.metadata) {
                return Err(ArchetypeError::SecretFieldRejected);
            }
            let identity = format!(
                "archetype-library-{}-{}",
                entry.repository_id,
                query_escape(&entry.slug)
            );
            let payload =
                serde_json::to_value(&entry).map_err(|_| ArchetypeError::InvalidResponse)?;
            let mut fields = compact([
                ("knowledge_slug", entry.slug.clone()),
                ("title", entry.title.clone()),
                ("scan_id", scan.id.to_string()),
                ("repository_id", entry.repository_id.to_string()),
                ("dominant_severity", entry.dominant_severity.clone()),
                ("topics", entry.topics.join(",")),
                ("generated_at", entry.generated_at.clone()),
                ("source_files", entry.source_files.join(",")),
                ("owner", entry.owner.clone()),
                ("repo", entry.repository_name.clone()),
            ]);
            for key in [
                "context_pack",
                "context_kind",
                "health_score",
                "freshness_state",
                "recommended_depth",
                "evidence_plane",
                "state_store",
                "context_stale",
                "needs_learning",
            ] {
                if let Some(value) = metadata_string(&entry.metadata, key) {
                    fields.insert(key.to_owned(), value);
                }
            }
            let record = self.adapt_record(
                request,
                observed_at,
                RecordParts {
                    provider_kind: "archetype.library_note",
                    provider_id: identity.clone(),
                    provider_occurred_at: scan.occurred_at.clone(),
                    fields,
                    payload,
                },
            )?;
            if let Some(index) = identities.get(&identity).copied() {
                if records.get(index) != Some(&record) {
                    return Err(ArchetypeError::DuplicateRecordIdentity);
                }
                continue;
            }
            identities.insert(identity, records.len());
            records.push(record);
        }
        Ok(records)
    }
}

fn metadata_string(metadata: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    match metadata.get(key)? {
        Value::String(value) => nonblank(value).map(str::to_owned),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn metadata_contains_secret_field(metadata: &BTreeMap<String, Value>) -> bool {
    metadata
        .iter()
        .any(|(key, value)| secret_field_name(key) || value_contains_secret_field(value))
}

fn value_contains_secret_field(value: &Value) -> bool {
    match value {
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| secret_field_name(key) || value_contains_secret_field(value)),
        Value::Array(values) => values.iter().any(value_contains_secret_field),
        _ => false,
    }
}

fn secret_field_name(name: &str) -> bool {
    let normalized = name
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' ', '.', '/'], "_");
    [
        "api_key",
        "authorization",
        "cookie",
        "credential",
        "password",
        "private_key",
        "secret",
        "token",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn query_escape(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                escaped.push(char::from(*byte));
            }
            b' ' => escaped.push('+'),
            _ => escaped.push_str(&format!("%{byte:02X}")),
        }
    }
    escaped
}

fn nonblank(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}
