use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::canonical_digest;

/// Tenant-scoped deposit request metadata accepted by the Rust runtime boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositIngestRequest {
    /// Tenant declared by the authenticated caller.
    pub tenant_id: String,
    /// Tenant that owns the source runtime.
    pub runtime_tenant_id: String,
    /// Source runtime receiving deposited records.
    pub runtime_id: String,
    /// Source/provider identifier.
    pub source_id: String,
    /// Source family receiving deposited records.
    pub family_id: String,
    /// Optional caller idempotency key, never echoed in receipts.
    pub idempotency_key: String,
    /// Number of accepted records.
    pub accepted: u32,
    /// Number of rejected or quarantined records.
    pub rejected: u32,
    /// Number of append-log events durably published.
    pub appended: u32,
    /// Number of projected entities.
    pub entities_projected: u32,
    /// Number of projected relationships.
    pub links_projected: u32,
    /// Authority evidence decision that permitted this family mode.
    pub authority_decision_id: String,
    /// Durable append-only authority evidence reference.
    pub authority_evidence_ref: String,
}

/// Deposit ingest receipt that mirrors scheduled page receipt semantics without
/// carrying raw record payloads or credential-bearing config.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DepositIngestReceipt {
    /// Stable deposit receipt ID.
    pub receipt_id: String,
    /// Append-log publication receipt.
    pub append_receipt_id: String,
    /// Graph projection receipt.
    pub projection_receipt_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Runtime scope.
    pub runtime_id: String,
    /// Source scope.
    pub source_id: String,
    /// Family scope.
    pub family_id: String,
    /// Accepted count.
    pub records_accepted: u32,
    /// Rejected count.
    pub records_rejected: u32,
    /// Appended event count.
    pub events_appended: u32,
    /// Projected entity count.
    pub entities_projected: u32,
    /// Projected link count.
    pub links_projected: u32,
    /// SHA-256 of the idempotency key, when supplied.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub idempotency_key_digest: String,
    /// Authority evidence decision referenced by this receipt.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub authority_decision_id: String,
    /// Durable append-only authority evidence reference.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub authority_evidence_ref: String,
    /// Canonical digest of this receipt.
    pub receipt_digest_sha256: String,
}

/// Deposit validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DepositIngestError {
    /// Runtime and request tenant scopes differ.
    TenantMismatch,
    /// Durable publication or projection receipt is missing.
    MissingReceiptEvidence,
}

/// Build a redacted, tenant-scoped deposit receipt.
pub fn build_deposit_receipt(
    request: &DepositIngestRequest,
) -> Result<DepositIngestReceipt, DepositIngestError> {
    if request.tenant_id.trim().is_empty()
        || request.tenant_id.trim() != request.runtime_tenant_id.trim()
    {
        return Err(DepositIngestError::TenantMismatch);
    }
    if request.appended > 0
        && (request.authority_decision_id.trim().is_empty()
            || request.authority_evidence_ref.trim().is_empty())
    {
        return Err(DepositIngestError::MissingReceiptEvidence);
    }
    let id_payload = serde_json::json!({
        "tenant_id": request.tenant_id,
        "runtime_id": request.runtime_id,
        "source_id": request.source_id,
        "family_id": request.family_id,
        "idempotency_key_digest": digest_optional(&request.idempotency_key),
        "accepted": request.accepted,
        "rejected": request.rejected,
        "appended": request.appended,
    });
    let receipt_id = format!("deposit:{}", canonical_digest(&id_payload));
    let mut receipt = DepositIngestReceipt {
        append_receipt_id: format!("append:{receipt_id}"),
        projection_receipt_id: format!("projection:{receipt_id}"),
        receipt_id,
        tenant_id: request.tenant_id.trim().to_owned(),
        runtime_id: request.runtime_id.trim().to_owned(),
        source_id: request.source_id.trim().to_owned(),
        family_id: request.family_id.trim().to_owned(),
        records_accepted: request.accepted,
        records_rejected: request.rejected,
        events_appended: request.appended,
        entities_projected: request.entities_projected,
        links_projected: request.links_projected,
        idempotency_key_digest: digest_optional(&request.idempotency_key),
        authority_decision_id: request.authority_decision_id.trim().to_owned(),
        authority_evidence_ref: request.authority_evidence_ref.trim().to_owned(),
        receipt_digest_sha256: String::new(),
    };
    receipt.receipt_digest_sha256 = canonical_digest(&receipt);
    Ok(receipt)
}

fn digest_optional(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return String::new();
    }
    let sum = Sha256::digest(value.as_bytes());
    sum.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_receipt_preserves_idempotency_redaction_and_receipt_semantics() {
        let receipt = build_deposit_receipt(&DepositIngestRequest {
            tenant_id: "tenant-a".to_owned(),
            runtime_tenant_id: "tenant-a".to_owned(),
            runtime_id: "runtime-deposit".to_owned(),
            source_id: "custom_deposit".to_owned(),
            family_id: "assets".to_owned(),
            idempotency_key: "SECRET-IDEMPOTENCY-KEY".to_owned(),
            accepted: 1,
            rejected: 1,
            appended: 1,
            entities_projected: 1,
            links_projected: 0,
            authority_decision_id: "decision-1".to_owned(),
            authority_evidence_ref: "authority-evidence:decision-1:7".to_owned(),
        })
        .unwrap();
        assert!(receipt.receipt_id.starts_with("deposit:"));
        assert!(receipt.append_receipt_id.starts_with("append:deposit:"));
        assert!(
            receipt
                .projection_receipt_id
                .starts_with("projection:deposit:")
        );
        assert_eq!(receipt.records_accepted, 1);
        assert_eq!(receipt.records_rejected, 1);
        assert_eq!(receipt.events_appended, 1);
        assert_eq!(receipt.idempotency_key_digest.len(), 64);
        assert_eq!(receipt.receipt_digest_sha256.len(), 64);
        let serialized = serde_json::to_string(&receipt).unwrap();
        assert!(!serialized.contains("SECRET-IDEMPOTENCY-KEY"));
        assert!(serialized.contains("decision-1"));
        assert!(serialized.contains("authority-evidence:decision-1:7"));
    }

    #[test]
    fn deposit_receipt_rejects_cross_tenant_and_missing_authority_evidence() {
        let mut request = DepositIngestRequest {
            tenant_id: "tenant-a".to_owned(),
            runtime_tenant_id: "tenant-b".to_owned(),
            runtime_id: "runtime-deposit".to_owned(),
            source_id: "custom_deposit".to_owned(),
            family_id: "assets".to_owned(),
            idempotency_key: "request-1".to_owned(),
            accepted: 1,
            rejected: 0,
            appended: 1,
            entities_projected: 1,
            links_projected: 0,
            authority_decision_id: "decision-1".to_owned(),
            authority_evidence_ref: "authority-evidence:decision-1:7".to_owned(),
        };
        assert_eq!(
            build_deposit_receipt(&request),
            Err(DepositIngestError::TenantMismatch)
        );
        request.runtime_tenant_id = "tenant-a".to_owned();
        request.authority_decision_id.clear();
        assert_eq!(
            build_deposit_receipt(&request),
            Err(DepositIngestError::MissingReceiptEvidence)
        );
        request.authority_decision_id = "decision-1".to_owned();
        request.authority_evidence_ref.clear();
        assert_eq!(
            build_deposit_receipt(&request),
            Err(DepositIngestError::MissingReceiptEvidence)
        );
    }
}
