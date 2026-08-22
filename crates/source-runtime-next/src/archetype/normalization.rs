use std::collections::BTreeMap;

use super::{
    ArchetypeError, ArchetypeFamily, ArchetypeKernel, ArchetypeRecord, ArchetypeRepository,
    ArchetypeRequest, ArchetypeRequestKind, ArchetypeScan, VulnerabilityCollectionState,
    adapter::{RecordParts, validate_enrichment_count, validate_response_size},
    types::{normalized_timestamp, valid_provider_id},
    wire::{RepositoryResponse, VulnerabilityResponse},
};

impl ArchetypeKernel {
    /// Decode repository identity enrichment into an ID-indexed map.
    pub fn decode_repositories(
        &self,
        request: &ArchetypeRequest,
        body: &[u8],
    ) -> Result<BTreeMap<u64, ArchetypeRepository>, ArchetypeError> {
        self.validate_request(request, ArchetypeRequestKind::Repositories, None)?;
        validate_response_size(body)?;
        let raw: Vec<RepositoryResponse> =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        validate_enrichment_count(raw.len())?;
        let mut repositories = BTreeMap::new();
        for repository in raw {
            if !valid_provider_id(repository.id) {
                return Err(ArchetypeError::MissingRecordIdentity);
            }
            let repository = ArchetypeRepository {
                id: repository.id,
                owner: repository.owner,
                name: repository.name,
            };
            if let Some(previous) = repositories.get(&repository.id) {
                if previous != &repository {
                    return Err(ArchetypeError::DuplicateRecordIdentity);
                }
                continue;
            }
            repositories.insert(repository.id, repository);
        }
        Ok(repositories)
    }

    /// Normalize a scan after its vulnerability collection state is known.
    pub fn scan_record(
        &self,
        request: &ArchetypeRequest,
        scan: &ArchetypeScan,
        repository: Option<&ArchetypeRepository>,
        collection_state: VulnerabilityCollectionState,
        observed_at: &str,
    ) -> Result<ArchetypeRecord, ArchetypeError> {
        scan.validate_invariant()?;
        self.validate_request(request, ArchetypeRequestKind::Scans, None)?;
        if scan.request_path != request.provenance() {
            return Err(ArchetypeError::RequestScopeMismatch);
        }
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
        self.adapt_record(
            request,
            observed_at,
            RecordParts {
                provider_kind: "archetype.scan",
                provider_id: format!("archetype-scan-{}", scan.id),
                provider_occurred_at: scan.occurred_at.clone(),
                fields,
                payload: scan.payload.clone(),
            },
        )
    }

    /// Decode and normalize vulnerabilities for the exact request-bound scan.
    pub fn decode_vulnerabilities(
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
            ArchetypeRequestKind::Vulnerabilities,
            Some(scan.id),
        )?;
        require_repository_scope(scan, repository)?;
        validate_response_size(body)?;
        let raw: Vec<VulnerabilityResponse> =
            serde_json::from_slice(body).map_err(|_| ArchetypeError::InvalidResponse)?;
        validate_enrichment_count(raw.len())?;
        let mut identities = BTreeMap::new();
        let mut records = Vec::with_capacity(raw.len());
        for vulnerability in raw {
            if !valid_provider_id(vulnerability.id) || !valid_provider_id(vulnerability.scan_id) {
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
            let record = self.adapt_record(
                request,
                observed_at,
                RecordParts {
                    provider_kind: "archetype.vulnerability",
                    provider_id: format!(
                        "archetype-vulnerability-{}-{}",
                        scan.id, vulnerability.id
                    ),
                    provider_occurred_at: normalized_timestamp(&vulnerability.created_at)
                        .or_else(|| scan.occurred_at.clone()),
                    fields,
                    payload,
                },
            )?;
            if let Some(index) = identities.get(&record.provider_id).copied() {
                if records.get(index) != Some(&record) {
                    return Err(ArchetypeError::DuplicateRecordIdentity);
                }
                continue;
            }
            identities.insert(record.provider_id.clone(), records.len());
            records.push(record);
        }
        Ok(records)
    }
}

pub(super) fn require_repository_scope(
    scan: &ArchetypeScan,
    repository: Option<&ArchetypeRepository>,
) -> Result<(), ArchetypeError> {
    if repository.is_some_and(|repository| repository.id != scan.repository_id) {
        return Err(ArchetypeError::ResponseScopeMismatch);
    }
    Ok(())
}

pub(super) fn compact<const N: usize>(values: [(&str, String); N]) -> BTreeMap<String, String> {
    values
        .into_iter()
        .filter_map(|(key, value)| (!value.trim().is_empty()).then(|| (key.to_owned(), value)))
        .collect()
}

pub(super) fn add_repository_fields(
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
