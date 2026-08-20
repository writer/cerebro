use std::collections::BTreeSet;

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Source-family authority decision kinds recorded in the append-only evidence stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityDecisionKind {
    /// Promote one tenant/source/family to Rust authority.
    Promotion,
    /// Roll back one tenant/source/family to the retained compatibility path.
    Rollback,
    /// Keep one tenant/source/family shadow-only with an auditable block reason.
    ShadowOnlyBlocked,
    /// Change runtime capability state without promoting the family.
    CapabilityChanged,
}

/// Immutable authority evidence for one tenant/source/family decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorityEvidenceRecord {
    /// Tenant scope.
    pub tenant_id: String,
    /// Source/provider scope.
    pub source_id: String,
    /// Source family scope.
    pub family_id: String,
    /// Monotonic authority epoch.
    pub authority_epoch: u64,
    /// Stable decision identifier.
    pub decision_id: String,
    /// Kind of authority decision.
    pub decision_kind: AuthorityDecisionKind,
    /// Digest of the input proof set.
    pub input_evidence_digest_sha256: String,
    /// Actor or system identity that made the decision.
    pub actor_id: String,
    /// Decision timestamp.
    pub timestamp_unix_ms: i64,
    /// Stable reason code.
    pub reason_code: String,
    /// Authenticated receipt identifier, when available.
    pub authenticated_receipt_id: String,
    /// Detached signature, when available.
    pub receipt_signature: String,
    /// Canonical record digest assigned at append time.
    pub record_digest_sha256: String,
}

/// Append-only source-family authority evidence stream.
#[derive(Default, Debug)]
pub struct AuthorityEvidenceStream {
    records: Vec<AuthorityEvidenceRecord>,
    decision_ids: BTreeSet<String>,
}

/// Authority evidence validation or immutability failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityEvidenceError {
    /// Record is malformed.
    Invalid(&'static str),
    /// Existing evidence cannot be changed.
    Immutable,
}

impl AuthorityEvidenceStream {
    /// Append one immutable authority evidence record.
    pub fn append(
        &mut self,
        mut record: AuthorityEvidenceRecord,
    ) -> Result<AuthorityEvidenceRecord, AuthorityEvidenceError> {
        validate_authority_evidence_record(&record)?;
        if !self
            .decision_ids
            .insert(record.decision_id.trim().to_owned())
        {
            return Err(AuthorityEvidenceError::Immutable);
        }
        record.record_digest_sha256.clear();
        record.record_digest_sha256 = digest_authority_evidence_record(&record);
        self.records.push(record.clone());
        Ok(record)
    }

    /// Return ordered authority history for one tenant/source/family.
    pub fn history(
        &self,
        tenant_id: &str,
        source_id: &str,
        family_id: &str,
    ) -> Vec<AuthorityEvidenceRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.tenant_id == tenant_id
                    && record.source_id == source_id
                    && record.family_id == family_id
            })
            .cloned()
            .collect()
    }

    /// Reject any post-append mutation to a stored record.
    pub fn mutate(
        &mut self,
        decision_id: &str,
        replacement: AuthorityEvidenceRecord,
    ) -> Result<(), AuthorityEvidenceError> {
        let Some(existing) = self
            .records
            .iter()
            .find(|record| record.decision_id == decision_id.trim())
        else {
            return Err(AuthorityEvidenceError::Invalid("decision_id"));
        };
        if existing == &replacement {
            return Ok(());
        }
        Err(AuthorityEvidenceError::Immutable)
    }
}

/// Validate an authority evidence record before any authority decision can use it.
pub fn validate_authority_evidence_record(
    record: &AuthorityEvidenceRecord,
) -> Result<(), AuthorityEvidenceError> {
    if record.tenant_id.trim().is_empty()
        || record.source_id.trim().is_empty()
        || record.family_id.trim().is_empty()
        || record.decision_id.trim().is_empty()
        || record.actor_id.trim().is_empty()
        || record.reason_code.trim().is_empty()
    {
        return Err(AuthorityEvidenceError::Invalid("required_identity"));
    }
    if record.authority_epoch == 0 {
        return Err(AuthorityEvidenceError::Invalid("authority_epoch"));
    }
    if !is_sha256_hex(&record.input_evidence_digest_sha256) {
        return Err(AuthorityEvidenceError::Invalid(
            "input_evidence_digest_sha256",
        ));
    }
    if record.decision_kind == AuthorityDecisionKind::Promotion
        && record.authenticated_receipt_id.trim().is_empty()
        && !record.receipt_signature.trim().starts_with("sig:")
    {
        return Err(AuthorityEvidenceError::Invalid("promotion_receipt"));
    }
    Ok(())
}

fn digest_authority_evidence_record(record: &AuthorityEvidenceRecord) -> String {
    let bytes = serde_json::to_vec(record).expect("authority evidence serializes");
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_sha256_hex(value: &str) -> bool {
    let value = value.trim();
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_evidence_stream_is_append_only_queryable_and_validated() {
        let mut stream = AuthorityEvidenceStream::default();
        let first = stream
            .append(authority_record(
                "decision-promote",
                1,
                AuthorityDecisionKind::Promotion,
            ))
            .unwrap();
        let second = stream
            .append(authority_record(
                "decision-rollback",
                2,
                AuthorityDecisionKind::Rollback,
            ))
            .unwrap();
        assert_eq!(first.record_digest_sha256.len(), 64);
        assert_eq!(second.record_digest_sha256.len(), 64);
        assert_ne!(first.record_digest_sha256, second.record_digest_sha256);
        let history = stream.history("tenant-a", "custom_deposit", "assets");
        assert_eq!(
            history
                .iter()
                .map(|record| record.decision_id.as_str())
                .collect::<Vec<_>>(),
            vec!["decision-promote", "decision-rollback"]
        );
        assert_eq!(
            stream.append(authority_record(
                "decision-promote",
                3,
                AuthorityDecisionKind::CapabilityChanged,
            )),
            Err(AuthorityEvidenceError::Immutable)
        );
        let mut mutated = first.clone();
        mutated.reason_code = "changed".to_owned();
        assert_eq!(
            stream.mutate(&first.decision_id, mutated),
            Err(AuthorityEvidenceError::Immutable)
        );

        let mut bad_digest =
            authority_record("decision-bad-digest", 4, AuthorityDecisionKind::Promotion);
        bad_digest.input_evidence_digest_sha256 = "not-a-sha".to_owned();
        assert_eq!(
            validate_authority_evidence_record(&bad_digest),
            Err(AuthorityEvidenceError::Invalid(
                "input_evidence_digest_sha256"
            ))
        );
        let mut unsigned =
            authority_record("decision-unsigned", 5, AuthorityDecisionKind::Promotion);
        unsigned.authenticated_receipt_id.clear();
        unsigned.receipt_signature.clear();
        assert_eq!(
            validate_authority_evidence_record(&unsigned),
            Err(AuthorityEvidenceError::Invalid("promotion_receipt"))
        );
        let mut blocked = unsigned;
        blocked.decision_kind = AuthorityDecisionKind::ShadowOnlyBlocked;
        assert_eq!(validate_authority_evidence_record(&blocked), Ok(()));
    }

    fn authority_record(
        decision_id: &str,
        authority_epoch: u64,
        decision_kind: AuthorityDecisionKind,
    ) -> AuthorityEvidenceRecord {
        AuthorityEvidenceRecord {
            tenant_id: "tenant-a".to_owned(),
            source_id: "custom_deposit".to_owned(),
            family_id: "assets".to_owned(),
            authority_epoch,
            decision_id: decision_id.to_owned(),
            decision_kind,
            input_evidence_digest_sha256: "a".repeat(64),
            actor_id: "system:cutover".to_owned(),
            timestamp_unix_ms: 1_787_136_000_000,
            reason_code: "provider_proof_complete".to_owned(),
            authenticated_receipt_id: "receipt:promotion".to_owned(),
            receipt_signature: String::new(),
            record_digest_sha256: String::new(),
        }
    }
}
