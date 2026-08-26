use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Source-family authority decision kinds recorded in the append-only evidence stream.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

/// Complete, non-secret proof bundle required for one source family to become
/// Rust-authoritative. Compile-time catalog flags are necessary but cannot
/// satisfy this runtime evidence contract by themselves.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityQualificationEvidence {
    pub plan_digest: String,
    pub runtime_plan_digest: String,
    pub fixture_corpus_revision: String,
    pub supported_auth_modes: Vec<String>,
    pub supported_pagination_grammar: Vec<String>,
    pub supported_provider_errors: Vec<String>,
    pub egress_allowlist: Vec<String>,
    pub response_limits: String,
    pub credential_lease_mode: String,
    pub projection_dependency: String,
    pub rollback_receipt: String,
    pub parity_status: String,
    pub canonical_digest_vectors: Vec<String>,
    pub config_safety_proof: String,
    pub cursor_checkpoint_proof: String,
    pub fencing_recovery_proof: String,
    pub worker_build_id: String,
    pub promotion_receipt: String,
    pub authenticated_collection_receipt: String,
    pub append_projection_checkpoint_receipt: String,
    pub lease_restart_receipt: String,
    pub product_read_receipt: String,
}

/// Immutable authority evidence for one tenant/source/family decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    /// Prior decision in the exact tenant/source/family authority chain.
    pub previous_decision_id: String,
    /// Complete proof bundle for a promotion decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualification: Option<AuthorityQualificationEvidence>,
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
        self.validate_append_sequence(&record)?;
        record.record_digest_sha256.clear();
        record.record_digest_sha256 = digest_authority_evidence_record(&record);
        self.insert_validated(record.clone())?;
        Ok(record)
    }

    /// Hydrate one already-persisted record after verifying its digest and
    /// monotonic family decision chain.
    pub fn append_persisted(
        &mut self,
        record: AuthorityEvidenceRecord,
    ) -> Result<(), AuthorityEvidenceError> {
        validate_authority_evidence_record(&record)?;
        if !is_sha256_hex(&record.record_digest_sha256)
            || digest_authority_evidence_record(&record) != record.record_digest_sha256
        {
            return Err(AuthorityEvidenceError::Invalid("record_digest_sha256"));
        }
        self.validate_append_sequence(&record)?;
        self.insert_validated(record)
    }

    fn insert_validated(
        &mut self,
        record: AuthorityEvidenceRecord,
    ) -> Result<(), AuthorityEvidenceError> {
        if !self
            .decision_ids
            .insert(record.decision_id.trim().to_owned())
        {
            return Err(AuthorityEvidenceError::Immutable);
        }
        self.records.push(record);
        Ok(())
    }

    fn validate_append_sequence(
        &self,
        record: &AuthorityEvidenceRecord,
    ) -> Result<(), AuthorityEvidenceError> {
        let previous = self.latest(&record.tenant_id, &record.source_id, &record.family_id);
        match previous {
            Some(previous)
                if record.authority_epoch == previous.authority_epoch + 1
                    && record.previous_decision_id == previous.decision_id =>
            {
                Ok(())
            }
            None if record.previous_decision_id.trim().is_empty() => Ok(()),
            _ => Err(AuthorityEvidenceError::Invalid("authority_sequence")),
        }
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

    /// Return the latest verified record for one exact authority scope.
    pub fn latest(
        &self,
        tenant_id: &str,
        source_id: &str,
        family_id: &str,
    ) -> Option<&AuthorityEvidenceRecord> {
        self.records.iter().rev().find(|record| {
            record.tenant_id == tenant_id
                && record.source_id == source_id
                && record.family_id == family_id
        })
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
    if record.authority_epoch == 0 || record.timestamp_unix_ms <= 0 {
        return Err(AuthorityEvidenceError::Invalid("authority_epoch"));
    }
    if !is_sha256_hex(&record.input_evidence_digest_sha256) {
        return Err(AuthorityEvidenceError::Invalid(
            "input_evidence_digest_sha256",
        ));
    }
    if record.decision_kind == AuthorityDecisionKind::Promotion {
        if record.authenticated_receipt_id.trim().is_empty()
            && !record.receipt_signature.trim().starts_with("sig:")
        {
            return Err(AuthorityEvidenceError::Invalid("promotion_receipt"));
        }
        let qualification = record
            .qualification
            .as_ref()
            .ok_or(AuthorityEvidenceError::Invalid("qualification_evidence"))?;
        validate_authority_qualification_evidence(qualification)?;
        if authority_qualification_digest(qualification)
            != record
                .input_evidence_digest_sha256
                .trim()
                .to_ascii_lowercase()
        {
            return Err(AuthorityEvidenceError::Invalid(
                "input_evidence_digest_sha256",
            ));
        }
    }
    Ok(())
}

/// Validate every exact receipt required before a promotion record is valid.
pub fn validate_authority_qualification_evidence(
    evidence: &AuthorityQualificationEvidence,
) -> Result<(), AuthorityEvidenceError> {
    let missing = missing_authority_qualification_evidence(evidence);
    if let Some(field) = missing.first() {
        return Err(AuthorityEvidenceError::Invalid(*field));
    }
    if !is_sha256_hex(&evidence.plan_digest) {
        return Err(AuthorityEvidenceError::Invalid("compiled_plan_digest"));
    }
    if !is_sha256_hex(&evidence.runtime_plan_digest) {
        return Err(AuthorityEvidenceError::Invalid("runtime_plan_digest"));
    }
    if !matches!(evidence.parity_status.trim(), "passed" | "matched") {
        return Err(AuthorityEvidenceError::Invalid("fixture_parity_status"));
    }
    let promotion = evidence.promotion_receipt.trim();
    if !promotion.starts_with("sig:") && !promotion.starts_with("auth:") {
        return Err(AuthorityEvidenceError::Invalid("promotion_receipt"));
    }
    Ok(())
}

/// Return stable field names for every absent authority proof.
pub fn missing_authority_qualification_evidence(
    evidence: &AuthorityQualificationEvidence,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if evidence.plan_digest.trim().is_empty() {
        missing.push("compiled_plan_digest");
    }
    if evidence.runtime_plan_digest.trim().is_empty() {
        missing.push("runtime_plan_digest");
    }
    if evidence.fixture_corpus_revision.trim().is_empty() {
        missing.push("fixture_corpus_revision");
    }
    for (field, values) in [
        ("supported_auth_modes", &evidence.supported_auth_modes),
        (
            "supported_pagination_grammar",
            &evidence.supported_pagination_grammar,
        ),
        (
            "supported_provider_error_modes",
            &evidence.supported_provider_errors,
        ),
        ("egress_allowlist", &evidence.egress_allowlist),
        (
            "canonical_digest_vectors",
            &evidence.canonical_digest_vectors,
        ),
    ] {
        if values.iter().all(|value| value.trim().is_empty()) {
            missing.push(field);
        }
    }
    for (field, value) in [
        ("response_decompression_limits", &evidence.response_limits),
        ("credential_lease_mode", &evidence.credential_lease_mode),
        ("projection_dependency", &evidence.projection_dependency),
        ("rollback_receipt", &evidence.rollback_receipt),
        ("fixture_parity_status", &evidence.parity_status),
        (
            "credential_config_safety_proof",
            &evidence.config_safety_proof,
        ),
        (
            "cursor_checkpoint_rollback_proof",
            &evidence.cursor_checkpoint_proof,
        ),
        (
            "operational_fencing_recovery_proof",
            &evidence.fencing_recovery_proof,
        ),
        ("worker_runtime_build_identity", &evidence.worker_build_id),
        ("promotion_receipt", &evidence.promotion_receipt),
        (
            "authenticated_collection_receipt",
            &evidence.authenticated_collection_receipt,
        ),
        (
            "append_projection_checkpoint_receipt",
            &evidence.append_projection_checkpoint_receipt,
        ),
        ("lease_restart_receipt", &evidence.lease_restart_receipt),
        ("product_read_receipt", &evidence.product_read_receipt),
    ] {
        if value.trim().is_empty() {
            missing.push(field);
        }
    }
    missing.sort_unstable();
    missing
}

/// Digest the canonical persisted proof bundle bound by a decision record.
pub fn authority_qualification_digest(evidence: &AuthorityQualificationEvidence) -> String {
    let bytes = serde_json::to_vec(evidence).expect("authority qualification serializes");
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest_authority_evidence_record(record: &AuthorityEvidenceRecord) -> String {
    let mut record = record.clone();
    record.record_digest_sha256.clear();
    let bytes = serde_json::to_vec(&record).expect("authority evidence serializes");
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

        let mut hydrated = AuthorityEvidenceStream::default();
        hydrated.append_persisted(first.clone()).unwrap();
        let mut tampered = second.clone();
        tampered.reason_code = "tampered".to_owned();
        assert_eq!(
            hydrated.append_persisted(tampered),
            Err(AuthorityEvidenceError::Invalid("record_digest_sha256"))
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

        let mut incomplete = qualification_evidence("a".repeat(64));
        incomplete.product_read_receipt.clear();
        assert_eq!(
            validate_authority_qualification_evidence(&incomplete),
            Err(AuthorityEvidenceError::Invalid("product_read_receipt"))
        );
    }

    fn authority_record(
        decision_id: &str,
        authority_epoch: u64,
        decision_kind: AuthorityDecisionKind,
    ) -> AuthorityEvidenceRecord {
        let qualification = (decision_kind == AuthorityDecisionKind::Promotion)
            .then(|| qualification_evidence("a".repeat(64)));
        let input_evidence_digest_sha256 = qualification
            .as_ref()
            .map_or_else(|| "a".repeat(64), authority_qualification_digest);
        AuthorityEvidenceRecord {
            tenant_id: "tenant-a".to_owned(),
            source_id: "custom_deposit".to_owned(),
            family_id: "assets".to_owned(),
            authority_epoch,
            decision_id: decision_id.to_owned(),
            decision_kind,
            input_evidence_digest_sha256,
            actor_id: "system:cutover".to_owned(),
            timestamp_unix_ms: 1_787_136_000_000,
            reason_code: "provider_proof_complete".to_owned(),
            authenticated_receipt_id: "receipt:promotion".to_owned(),
            receipt_signature: String::new(),
            previous_decision_id: match authority_epoch {
                1 => String::new(),
                2 => "decision-promote".to_owned(),
                _ => "decision-rollback".to_owned(),
            },
            qualification,
            record_digest_sha256: String::new(),
        }
    }

    fn qualification_evidence(plan_digest: String) -> AuthorityQualificationEvidence {
        AuthorityQualificationEvidence {
            plan_digest,
            runtime_plan_digest: "b".repeat(64),
            fixture_corpus_revision: "fixture-corpus:v1".to_owned(),
            supported_auth_modes: vec!["api_key".to_owned()],
            supported_pagination_grammar: vec!["cursor".to_owned()],
            supported_provider_errors: vec!["unauthorized".to_owned(), "rate_limited".to_owned()],
            egress_allowlist: vec!["https://provider.example.test".to_owned()],
            response_limits: "body=1048576,decompression=4x".to_owned(),
            credential_lease_mode: "one_operation".to_owned(),
            projection_dependency: "rust_projection".to_owned(),
            rollback_receipt: "receipt:rollback".to_owned(),
            parity_status: "passed".to_owned(),
            canonical_digest_vectors: vec!["plan".to_owned(), "result".to_owned()],
            config_safety_proof: "receipt:config-safety".to_owned(),
            cursor_checkpoint_proof: "receipt:cursor-checkpoint".to_owned(),
            fencing_recovery_proof: "receipt:fencing-recovery".to_owned(),
            worker_build_id: "source-runtime-next:test".to_owned(),
            promotion_receipt: "sig:promotion:test".to_owned(),
            authenticated_collection_receipt: "receipt:collection".to_owned(),
            append_projection_checkpoint_receipt: "receipt:durable-commit".to_owned(),
            lease_restart_receipt: "receipt:lease-restart".to_owned(),
            product_read_receipt: "receipt:product-read".to_owned(),
        }
    }
}
