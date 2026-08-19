use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

const PROTOCOL_REVISION: u16 = 1;

/// Versioned source-runtime operations that a worker may execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum SourceRuntimeOperation {
    /// Compile or describe a deterministic execution plan.
    DescribePlan,
    /// Validate provider reachability and configuration without committing state.
    Check,
    /// Discover provider scopes without committing runtime progress.
    Discover,
    /// Read one bounded provider page.
    ReadPage,
}

/// Versioned request/result/receipt/error envelope shared with Go conformance tests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceRuntimeEnvelope {
    /// Protocol schema revision. Unknown revisions fail closed.
    pub revision: u16,
    /// Worker-side operation. Durable sync/commit is intentionally absent.
    pub operation: SourceRuntimeOperation,
    /// Tenant boundary for this attempt.
    pub tenant_id: String,
    /// Durable source-runtime instance.
    pub runtime_id: String,
    /// Source/provider identifier.
    pub source_id: String,
    /// Runtime family identifier.
    pub family_id: String,
    /// Unique page/check/discover attempt identifier.
    pub attempt_id: String,
    /// Public, non-secret config only.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub public_config: BTreeMap<String, String>,
    /// Go-compatible page cursor input.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cursor: String,
    /// Go-compatible checkpoint input digest or opaque value.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub checkpoint: String,
    /// Page/event limit.
    #[serde(skip_serializing_if = "is_zero")]
    pub limit: u32,
    /// Optional normalized result shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SourceRuntimeResult>,
    /// Optional worker receipt shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<SourceRuntimeReceipt>,
    /// Optional redacted error shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SourceRuntimeErrorShape>,
}

/// Normalized worker result summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceRuntimeResult {
    /// Accepted event count.
    pub events_accepted: u32,
    /// Scanned event count.
    pub events_scanned: u32,
    /// Next page cursor, when present.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub next_cursor: String,
    /// Redacted diagnostics.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub diagnostics: BTreeMap<String, String>,
}

/// Worker receipt digest payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceRuntimeReceipt {
    /// Canonical plan SHA-256 digest.
    pub plan_digest_sha256: String,
    /// Request intent SHA-256 digest.
    pub request_digest_sha256: String,
    /// Scanned event set SHA-256 digest.
    pub scanned_digest_sha256: String,
    /// Accepted event set SHA-256 digest.
    pub accepted_digest_sha256: String,
    /// Logical result SHA-256 digest.
    pub result_digest_sha256: String,
    /// Receipt payload SHA-256 digest.
    pub receipt_digest_sha256: String,
    /// Worker/runtime build identity.
    pub worker_build_id: String,
    /// Runtime-family provider proof revision.
    pub runtime_family_proof_revision: String,
}

/// Redacted worker error shape.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceRuntimeErrorShape {
    /// Stable error code.
    pub code: String,
    /// Stable error category.
    pub category: String,
    /// Whether retrying the same request may succeed.
    pub retryable: bool,
    /// Redacted diagnostics.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub diagnostics: BTreeMap<String, String>,
}

/// Complete evidence required before source-family Rust authority promotion.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorityEvidence {
    /// Compiled execution plan digest.
    pub plan_digest: String,
    /// Fixture corpus revision.
    pub fixture_corpus_revision: String,
    /// Supported auth modes.
    pub supported_auth_modes: Vec<String>,
    /// Supported pagination grammar entries.
    pub supported_pagination_grammar: Vec<String>,
    /// Supported provider error modes.
    pub supported_provider_errors: Vec<String>,
    /// Bounded provider egress allowlist.
    pub egress_allowlist: Vec<String>,
    /// Response and decompression limits proof.
    pub response_limits: String,
    /// Credential lease mode proof.
    pub credential_lease_mode: String,
    /// Projection readiness or explicit Go dependency.
    pub projection_dependency: String,
    /// Rollback receipt.
    pub rollback_receipt: String,
    /// Fixture parity status.
    pub parity_status: String,
    /// Canonical digest vector names.
    pub canonical_digest_vectors: Vec<String>,
    /// Credential/config safety proof.
    pub config_safety_proof: String,
    /// Cursor/checkpoint rollback proof.
    pub cursor_checkpoint_proof: String,
    /// Fencing/recovery proof.
    pub fencing_recovery_proof: String,
    /// Worker/runtime build identity.
    pub worker_build_id: String,
    /// Signed or authenticated promotion receipt.
    pub promotion_receipt: String,
}

/// Protocol validation failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// Unknown schema revision.
    UnknownRevision(u16),
    /// Required identity was absent.
    MissingIdentity(&'static str),
    /// Raw-secret capable field was present.
    RawSecretField(String),
    /// Authority evidence is incomplete.
    MissingAuthorityEvidence(Vec<&'static str>),
}

/// Validate a source-runtime envelope.
pub fn validate_envelope(envelope: &SourceRuntimeEnvelope) -> Result<(), ProtocolError> {
    if envelope.revision != PROTOCOL_REVISION {
        return Err(ProtocolError::UnknownRevision(envelope.revision));
    }
    for (field, value) in [
        ("tenant_id", &envelope.tenant_id),
        ("runtime_id", &envelope.runtime_id),
        ("source_id", &envelope.source_id),
        ("family_id", &envelope.family_id),
        ("attempt_id", &envelope.attempt_id),
    ] {
        if value.trim().is_empty() {
            return Err(ProtocolError::MissingIdentity(field));
        }
    }
    let value = serde_json::to_value(envelope).expect("source-runtime envelope serializes");
    if let Some(path) = first_raw_secret_field("", &value) {
        return Err(ProtocolError::RawSecretField(path));
    }
    Ok(())
}

/// Validate complete provider proof before authority promotion.
pub fn validate_authority_evidence(evidence: &AuthorityEvidence) -> Result<(), ProtocolError> {
    let missing = missing_authority_evidence(evidence);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::MissingAuthorityEvidence(missing))
    }
}

/// Return canonical SHA-256 hex for a serializable JSON/protobuf-shaped value.
pub fn canonical_digest(value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("canonical value serializes");
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes);
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_canonical_json(value: &serde_json::Value, out: &mut Vec<u8>) {
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            out.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        serde_json::Value::Number(value) => out.extend_from_slice(value.to_string().as_bytes()),
        serde_json::Value::String(value) => {
            serde_json::to_writer(out, value).expect("canonical string serializes");
        }
        serde_json::Value::Array(values) => {
            out.push(b'[');
            for (idx, value) in values.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical_json(value, out);
            }
            out.push(b']');
        }
        serde_json::Value::Object(values) => {
            out.push(b'{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            for (idx, key) in keys.into_iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).expect("canonical object key serializes");
                out.push(b':');
                write_canonical_json(&values[key], out);
            }
            out.push(b'}');
        }
    }
}

/// Return the canonical digest vectors shared with the Go conformance tests.
pub fn canonical_digest_vectors() -> BTreeMap<&'static str, String> {
    let plan = json!({
        "family_id": "identity_user",
        "limits": {
            "event_limit": 250,
            "page_size": 100,
        },
        "operation": "ReadPage",
        "public_config": {
            "base_url": "https://provider.example.invalid",
            "org": "writer",
        },
        "source_id": "fixture",
    });
    let request = fixture_envelope(SourceRuntimeOperation::ReadPage);
    let scanned = json!([
        {"event_id": "evt-1", "kind": "fixture.identity_user", "provider_id": "u-1"},
        {"event_id": "evt-2", "kind": "fixture.identity_user", "provider_id": "u-2"}
    ]);
    let accepted = json!([
        {"event_id": "evt-1", "kind": "fixture.identity_user", "provider_id": "u-1"}
    ]);
    let result = SourceRuntimeResult {
        events_scanned: 2,
        events_accepted: 1,
        next_cursor: "cursor-2".to_owned(),
        diagnostics: BTreeMap::from([(
            "redaction".to_owned(),
            "provider diagnostics redacted".to_owned(),
        )]),
    };
    let mut out = BTreeMap::from([
        ("plan", canonical_digest(&plan)),
        ("request_intent", canonical_digest(&request)),
        ("scanned_events", canonical_digest(&scanned)),
        ("accepted_events", canonical_digest(&accepted)),
        ("logical_result", canonical_digest(&result)),
    ]);
    let receipt = SourceRuntimeReceipt {
        plan_digest_sha256: out["plan"].clone(),
        request_digest_sha256: out["request_intent"].clone(),
        scanned_digest_sha256: out["scanned_events"].clone(),
        accepted_digest_sha256: out["accepted_events"].clone(),
        result_digest_sha256: out["logical_result"].clone(),
        receipt_digest_sha256: String::new(),
        worker_build_id: "source-runtime-next:test".to_owned(),
        runtime_family_proof_revision: "fixture-corpus:v1".to_owned(),
    };
    out.insert("worker_receipt", canonical_digest(&receipt));
    out
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

fn first_raw_secret_field(path: &str, value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let next = if path.is_empty() {
                    key.to_owned()
                } else {
                    format!("{path}.{key}")
                };
                if raw_secret_field_name(key) {
                    return Some(next);
                }
                if let Some(found) = first_raw_secret_field(&next, child) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                let next = format!("{path}[{index}]");
                if let Some(found) = first_raw_secret_field(&next, child) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

fn raw_secret_field_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace(['-', ' '], "_");
    [
        "raw_credential",
        "credential_value",
        "secret",
        "token",
        "cookie",
        "authorization_header",
        "client_secret",
        "raw_provider_http_request_body",
        "raw_provider_http_response_body",
        "raw_provider_error_body",
        "raw_provider_payload",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn missing_authority_evidence(evidence: &AuthorityEvidence) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if evidence.plan_digest.trim().is_empty() {
        missing.push("compiled_plan_digest");
    }
    if evidence.fixture_corpus_revision.trim().is_empty() {
        missing.push("fixture_corpus_revision");
    }
    if evidence
        .supported_auth_modes
        .iter()
        .all(|value| value.trim().is_empty())
    {
        missing.push("supported_auth_modes");
    }
    if evidence
        .supported_pagination_grammar
        .iter()
        .all(|value| value.trim().is_empty())
    {
        missing.push("supported_pagination_grammar");
    }
    if evidence
        .supported_provider_errors
        .iter()
        .all(|value| value.trim().is_empty())
    {
        missing.push("supported_provider_error_modes");
    }
    if evidence
        .egress_allowlist
        .iter()
        .all(|value| value.trim().is_empty())
    {
        missing.push("egress_allowlist");
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
    ] {
        if value.trim().is_empty() {
            missing.push(field);
        }
    }
    if evidence
        .canonical_digest_vectors
        .iter()
        .all(|value| value.trim().is_empty())
    {
        missing.push("canonical_digest_vectors");
    }
    missing.sort_unstable();
    missing
}

#[cfg(test)]
pub(crate) fn fixture_envelope(operation: SourceRuntimeOperation) -> SourceRuntimeEnvelope {
    SourceRuntimeEnvelope {
        revision: PROTOCOL_REVISION,
        operation,
        tenant_id: "tenant-a".to_owned(),
        runtime_id: "runtime-a".to_owned(),
        source_id: "fixture".to_owned(),
        family_id: "identity_user".to_owned(),
        attempt_id: "attempt-0001".to_owned(),
        public_config: BTreeMap::from([
            (
                "base_url".to_owned(),
                "https://provider.example.invalid".to_owned(),
            ),
            ("org".to_owned(), "writer".to_owned()),
        ]),
        cursor: "cursor-1".to_owned(),
        checkpoint: "checkpoint-1".to_owned(),
        limit: 100,
        result: None,
        receipt: None,
        error: None,
    }
}

#[cfg(not(test))]
fn fixture_envelope(operation: SourceRuntimeOperation) -> SourceRuntimeEnvelope {
    SourceRuntimeEnvelope {
        revision: PROTOCOL_REVISION,
        operation,
        tenant_id: "tenant-a".to_owned(),
        runtime_id: "runtime-a".to_owned(),
        source_id: "fixture".to_owned(),
        family_id: "identity_user".to_owned(),
        attempt_id: "attempt-0001".to_owned(),
        public_config: BTreeMap::from([
            (
                "base_url".to_owned(),
                "https://provider.example.invalid".to_owned(),
            ),
            ("org".to_owned(), "writer".to_owned()),
        ]),
        cursor: "cursor-1".to_owned(),
        checkpoint: "checkpoint-1".to_owned(),
        limit: 100,
        result: None,
        receipt: None,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_runtime_protocol_contract_accepts_and_rejects_expected_shapes() {
        for operation in [
            SourceRuntimeOperation::DescribePlan,
            SourceRuntimeOperation::Check,
            SourceRuntimeOperation::Discover,
            SourceRuntimeOperation::ReadPage,
        ] {
            validate_envelope(&fixture_envelope(operation)).unwrap();
        }

        let mut unknown_revision = fixture_envelope(SourceRuntimeOperation::ReadPage);
        unknown_revision.revision = 99;
        assert_eq!(
            validate_envelope(&unknown_revision),
            Err(ProtocolError::UnknownRevision(99))
        );

        let mut missing_tenant = fixture_envelope(SourceRuntimeOperation::ReadPage);
        missing_tenant.tenant_id.clear();
        assert_eq!(
            validate_envelope(&missing_tenant),
            Err(ProtocolError::MissingIdentity("tenant_id"))
        );

        let mut raw_secret = fixture_envelope(SourceRuntimeOperation::ReadPage);
        raw_secret
            .public_config
            .insert("api_token".to_owned(), "sentinel".to_owned());
        assert!(matches!(
            validate_envelope(&raw_secret),
            Err(ProtocolError::RawSecretField(path)) if path == "public_config.api_token"
        ));
        println!(
            "source_runtime_protocol_contract accepted=DescribePlan,Check,Discover,ReadPage rejected=unknown_revision,missing_tenant,raw_secret raw_secret_fields=[]"
        );
    }

    #[test]
    fn canonical_digest_vectors_are_stable() {
        let vectors = canonical_digest_vectors();
        let repeated = canonical_digest_vectors();
        assert_eq!(vectors, repeated);
        for (name, digest) in &vectors {
            assert_eq!(digest.len(), 64, "{name}");
        }
        let permuted = json!({
            "source_id": "fixture",
            "public_config": {
                "org": "writer",
                "base_url": "https://provider.example.invalid",
            },
            "operation": "ReadPage",
            "limits": {
                "page_size": 100,
                "event_limit": 250,
            },
            "family_id": "identity_user",
        });
        assert_eq!(vectors["plan"], canonical_digest(&permuted));
        println!("canonical_digest_vectors={vectors:?}");
    }

    #[test]
    fn authority_readiness_requires_complete_evidence() {
        let complete = AuthorityEvidence {
            plan_digest: "a".repeat(64),
            fixture_corpus_revision: "fixture-corpus:v1".to_owned(),
            supported_auth_modes: vec!["api_key".to_owned()],
            supported_pagination_grammar: vec!["cursor".to_owned()],
            supported_provider_errors: vec!["401".to_owned(), "429".to_owned(), "5xx".to_owned()],
            egress_allowlist: vec!["https://provider.example.invalid".to_owned()],
            response_limits: "body=1048576,decompression=4x".to_owned(),
            credential_lease_mode: "one_operation".to_owned(),
            projection_dependency: "go_projection_dependency".to_owned(),
            rollback_receipt: "rollback:test".to_owned(),
            parity_status: "passed".to_owned(),
            canonical_digest_vectors: vec![
                "plan".to_owned(),
                "request_intent".to_owned(),
                "worker_receipt".to_owned(),
            ],
            config_safety_proof: "config:redacted".to_owned(),
            cursor_checkpoint_proof: "cursor:go-compatible".to_owned(),
            fencing_recovery_proof: "fence:rejected-stale".to_owned(),
            worker_build_id: "source-runtime-next:test".to_owned(),
            promotion_receipt: "promotion:test".to_owned(),
        };
        validate_authority_evidence(&complete).unwrap();

        let mut incomplete = complete;
        incomplete.rollback_receipt.clear();
        incomplete.egress_allowlist.clear();
        let Err(ProtocolError::MissingAuthorityEvidence(missing)) =
            validate_authority_evidence(&incomplete)
        else {
            panic!("incomplete provider proof accepted")
        };
        assert!(missing.contains(&"egress_allowlist"));
        assert!(missing.contains(&"rollback_receipt"));
    }
}
