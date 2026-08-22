//! Provider-local event materialization for Archetype records.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    ArchetypeError, ArchetypeKernel, ArchetypeRecord, ArchetypeRequest, types::normalized_timestamp,
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 << 20;
pub(super) const MAX_ENRICHMENT_RECORDS: usize = 500;
const MAX_TENANT_ID_BYTES: usize = 256;

pub(super) struct RecordParts {
    pub(super) provider_kind: &'static str,
    pub(super) provider_id: String,
    pub(super) provider_occurred_at: Option<String>,
    pub(super) fields: BTreeMap<String, String>,
    pub(super) payload: Value,
}

impl ArchetypeKernel {
    /// Bind the tenant identity supplied by the trusted runtime context.
    ///
    /// Provider responses cannot override this identity. The kernel still does
    /// not accept credentials or perform network I/O.
    pub fn bind_tenant(mut self, tenant_id: &str) -> Result<Self, ArchetypeError> {
        let tenant_id = tenant_id.trim();
        if tenant_id.is_empty()
            || tenant_id.len() > MAX_TENANT_ID_BYTES
            || tenant_id.chars().any(char::is_control)
        {
            return Err(ArchetypeError::MissingTenantId);
        }
        self.tenant_id = Some(tenant_id.to_owned());
        Ok(self)
    }

    /// Return whether this credential-free planning and decoding kernel accepts secrets.
    pub const fn requires_credentials() -> bool {
        false
    }

    pub(super) fn adapt_record(
        &self,
        request: &ArchetypeRequest,
        observed_at: &str,
        parts: RecordParts,
    ) -> Result<ArchetypeRecord, ArchetypeError> {
        let RecordParts {
            provider_kind,
            provider_id,
            provider_occurred_at,
            fields,
            payload,
        } = parts;
        let tenant_id = self
            .tenant_id
            .as_deref()
            .ok_or(ArchetypeError::MissingTenantId)?;
        let observed_at =
            normalized_timestamp(observed_at).ok_or(ArchetypeError::InvalidObservedAt)?;
        let schema_ref = match provider_kind {
            "archetype.scan" => "archetype/scan/v1",
            "archetype.vulnerability" => "archetype/vulnerability/v1",
            "archetype.library_note" => "archetype/library-note/v1",
            _ => return Err(ArchetypeError::InvalidResponse),
        };
        Ok(ArchetypeRecord {
            family: self.family.as_str().to_owned(),
            source_id: "archetype".to_owned(),
            provider_kind: provider_kind.to_owned(),
            schema_ref: schema_ref.to_owned(),
            tenant_id: tenant_id.to_owned(),
            event_id: provider_id.clone(),
            provider_id,
            request_kind: request.kind.as_str().to_owned(),
            request_path: request.provenance(),
            occurred_at: provider_occurred_at.unwrap_or(observed_at),
            fields,
            payload,
        })
    }
}

pub(super) fn validate_response_size(body: &[u8]) -> Result<(), ArchetypeError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(ArchetypeError::ResponseTooLarge);
    }
    Ok(())
}

pub(super) fn validate_enrichment_count(record_count: usize) -> Result<(), ArchetypeError> {
    if record_count > MAX_ENRICHMENT_RECORDS {
        return Err(ArchetypeError::TooManyRecords);
    }
    Ok(())
}
