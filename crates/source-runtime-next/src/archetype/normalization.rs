use std::collections::{BTreeMap, HashSet};

use serde_json::Value;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::{
    ArchetypeError, ArchetypeFamily, ArchetypeKernel, ArchetypeRecord, ArchetypeRepository,
    ArchetypeRequest, ArchetypeRequestKind, ArchetypeScan, VulnerabilityCollectionState,
    wire::{KnowledgeResponse, RepositoryResponse, VulnerabilityResponse},
};

impl ArchetypeKernel {
    /// Decode repository identity enrichment into an ID-indexed map.
    pub fn decode_repositories(
        &self,
        request: &ArchetypeRequest,
        body: &[u8],
    ) -> Result<BTreeMap<u64, ArchetypeRepository>, ArchetypeError> {
        self.validate_request(request, ArchetypeRequestKind::Repositories, None)?;
        let raw: Vec<RepositoryResponse> =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        let mut repositories = BTreeMap::new();
        for repository in raw {
            if repository.id == 0 {
                return Err(ArchetypeError::MissingRecordIdentity);
            }
            let repository = ArchetypeRepository {
                id: repository.id,
                owner: repository.owner,
                name: repository.name,
            };
            if repositories.insert(repository.id, repository).is_some() {
                return Err(ArchetypeError::DuplicateRecordIdentity);
            }
        }
        Ok(repositories)
    }

    /// Normalize a scan after its vulnerability collection state is known.
    pub fn scan_record(
        &self,
        scan: &ArchetypeScan,
        repository: Option<&ArchetypeRepository>,
        collection_state: VulnerabilityCollectionState,
    ) -> Result<ArchetypeRecord, ArchetypeError> {
        require_repository_scope(scan, repository)?;
        match (self.family, collection_state) {
            (ArchetypeFamily::Scan, VulnerabilityCollectionState::NotRequested)
            | (ArchetypeFamily::Vulnerability, VulnerabilityCollectionState::Unavailable)
            | (ArchetypeFamily::Vulnerability, VulnerabilityCollectionState::Complete) => {}
            _ => return Err(ArchetypeError::CollectionStateMismatch),
        }
        let mut fields = compact([
            ("scan_id", scan.id.to_string()),
            ("repository_id", scan.repository_id.to_string()),
            ("status", scan.status.clone()),
            ("source_product", "archetype".to_owned()),
            (
                "vulnerability_collection_state",
                collection_state.as_str().to_owned(),
            ),
        ]);
        add_repository_fields(&mut fields, repository);
        Ok(ArchetypeRecord {
            family: self.family.as_str().to_owned(),
            provider_kind: "archetype.scan".to_owned(),
            provider_id: format!("archetype-scan-{}", scan.id),
            occurred_at: scan.occurred_at.clone(),
            fields,
            payload: scan.payload.clone(),
        })
    }

    /// Decode and normalize vulnerabilities for the exact request-bound scan.
    pub fn decode_vulnerabilities(
        &self,
        request: &ArchetypeRequest,
        body: &[u8],
        scan: &ArchetypeScan,
        repository: Option<&ArchetypeRepository>,
    ) -> Result<Vec<ArchetypeRecord>, ArchetypeError> {
        self.require_vulnerability_family()?;
        self.validate_request(
            request,
            ArchetypeRequestKind::Vulnerabilities,
            Some(scan.id),
        )?;
        require_repository_scope(scan, repository)?;
        let raw: Vec<VulnerabilityResponse> =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        let mut identities = HashSet::new();
        raw.into_iter()
            .map(|vulnerability| {
                if vulnerability.id == 0 || vulnerability.scan_id == 0 {
                    return Err(ArchetypeError::MissingRecordIdentity);
                }
                if vulnerability.scan_id != scan.id {
                    return Err(ArchetypeError::ResponseScopeMismatch);
                }
                if vulnerability.severity.trim().is_empty()
                    || vulnerability.category.trim().is_empty()
                    || vulnerability.file_path.trim().is_empty()
                {
                    return Err(ArchetypeError::InvalidResponse);
                }
                if !identities.insert(vulnerability.id) {
                    return Err(ArchetypeError::DuplicateRecordIdentity);
                }
                let payload = serde_json::to_value(&vulnerability)
                    .map_err(|_| ArchetypeError::InvalidResponse)?;
                let mut fields = compact([
                    ("vulnerability_id", vulnerability.id.to_string()),
                    ("scan_id", vulnerability.scan_id.to_string()),
                    ("repository_id", scan.repository_id.to_string()),
                    ("severity", vulnerability.severity.clone()),
                    ("category", vulnerability.category.clone()),
                    ("file_path", vulnerability.file_path.clone()),
                    ("line_number", vulnerability.line_number.to_string()),
                    ("source_product", "archetype".to_owned()),
                ]);
                add_repository_fields(&mut fields, repository);
                Ok(ArchetypeRecord {
                    family: self.family.as_str().to_owned(),
                    provider_kind: "archetype.vulnerability".to_owned(),
                    provider_id: format!(
                        "archetype-vulnerability-{}-{}",
                        scan.id, vulnerability.id
                    ),
                    occurred_at: normalized_timestamp(&vulnerability.created_at)
                        .or_else(|| scan.occurred_at.clone()),
                    fields,
                    payload,
                })
            })
            .collect()
    }

    /// Decode and normalize repository knowledge for the request-bound scan.
    pub fn decode_knowledge(
        &self,
        request: &ArchetypeRequest,
        body: &[u8],
        scan: &ArchetypeScan,
        repository: Option<&ArchetypeRepository>,
    ) -> Result<Vec<ArchetypeRecord>, ArchetypeError> {
        self.require_vulnerability_family()?;
        self.validate_request(
            request,
            ArchetypeRequestKind::Knowledge,
            Some(scan.repository_id),
        )?;
        require_repository_scope(scan, repository)?;
        let response: KnowledgeResponse =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        let mut identities = HashSet::new();
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
            let identity = format!(
                "archetype-library-{}-{}",
                entry.repository_id,
                query_escape(&entry.slug)
            );
            if !identities.insert(identity.clone()) {
                return Err(ArchetypeError::DuplicateRecordIdentity);
            }
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
            records.push(ArchetypeRecord {
                family: self.family.as_str().to_owned(),
                provider_kind: "archetype.library_note".to_owned(),
                provider_id: identity,
                occurred_at: scan.occurred_at.clone(),
                fields,
                payload,
            });
        }
        Ok(records)
    }
}

fn require_repository_scope(
    scan: &ArchetypeScan,
    repository: Option<&ArchetypeRepository>,
) -> Result<(), ArchetypeError> {
    if repository.is_some_and(|repository| repository.id != scan.repository_id) {
        return Err(ArchetypeError::ResponseScopeMismatch);
    }
    Ok(())
}

fn compact<const N: usize>(values: [(&str, String); N]) -> BTreeMap<String, String> {
    values
        .into_iter()
        .filter_map(|(key, value)| (!value.trim().is_empty()).then(|| (key.to_owned(), value)))
        .collect()
}

fn add_repository_fields(
    fields: &mut BTreeMap<String, String>,
    repository: Option<&ArchetypeRepository>,
) {
    if let Some(repository) = repository {
        if !repository.owner.trim().is_empty() {
            fields.insert("owner".to_owned(), repository.owner.clone());
        }
        if !repository.name.trim().is_empty() {
            fields.insert("repo".to_owned(), repository.name.clone());
        }
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

pub(super) fn normalized_timestamp(value: &str) -> Option<String> {
    let parsed = OffsetDateTime::parse(value.trim(), &Rfc3339).ok()?;
    parsed.to_offset(UtcOffset::UTC).format(&Rfc3339).ok()
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
