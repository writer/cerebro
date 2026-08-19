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
    /// Unsupported or worker-only operation.
    UnsupportedOperation(String),
    /// Required identity was absent.
    MissingIdentity(&'static str),
    /// Raw-secret capable field was present.
    RawSecretField(String),
    /// Authority evidence is incomplete.
    MissingAuthorityEvidence(Vec<&'static str>),
    /// Authority proof digest is not a SHA-256 hexadecimal digest.
    InvalidAuthorityDigest(&'static str),
    /// Promotion receipt is neither signed nor authenticated.
    UnauthenticatedPromotionReceipt,
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

/// Validate a decoded JSON source-runtime envelope before typed callers accept it.
///
/// This gives downstream Rust callers an observable fail-closed path for
/// invalid protocol envelopes that cannot be represented by the typed
/// `SourceRuntimeEnvelope`, such as worker `Sync` operations or unknown
/// operation strings.
pub fn validate_envelope_json(value: &serde_json::Value) -> Result<(), ProtocolError> {
    let revision = value
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or_default();
    if revision != PROTOCOL_REVISION {
        return Err(ProtocolError::UnknownRevision(revision));
    }
    let operation = value
        .get("operation")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    match operation {
        "DescribePlan" | "Check" | "Discover" | "ReadPage" => {}
        other => return Err(ProtocolError::UnsupportedOperation(other.to_owned())),
    }
    for field in [
        "tenant_id",
        "runtime_id",
        "source_id",
        "family_id",
        "attempt_id",
    ] {
        let present = value
            .get(field)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty());
        if !present {
            return Err(ProtocolError::MissingIdentity(field));
        }
    }
    if let Some(path) = first_raw_secret_field("", value) {
        return Err(ProtocolError::RawSecretField(path));
    }
    Ok(())
}

/// Validate complete provider proof before authority promotion.
pub fn validate_authority_evidence(evidence: &AuthorityEvidence) -> Result<(), ProtocolError> {
    let missing = missing_authority_evidence(evidence);
    if !missing.is_empty() {
        return Err(ProtocolError::MissingAuthorityEvidence(missing));
    }
    if !is_sha256_hex(&evidence.plan_digest) {
        return Err(ProtocolError::InvalidAuthorityDigest(
            "compiled_plan_digest",
        ));
    }
    if !authenticated_promotion_receipt(&evidence.promotion_receipt) {
        return Err(ProtocolError::UnauthenticatedPromotionReceipt);
    }
    Ok(())
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
            write_go_json_string(out, value);
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
                write_go_json_string(out, key);
                out.push(b':');
                write_canonical_json(&values[key], out);
            }
            out.push(b'}');
        }
    }
}

fn write_go_json_string(out: &mut Vec<u8>, value: &str) {
    let encoded = serde_json::to_string(value).expect("canonical string serializes");
    for character in encoded.chars() {
        match character {
            '<' => out.extend_from_slice(b"\\u003c"),
            '>' => out.extend_from_slice(b"\\u003e"),
            '&' => out.extend_from_slice(b"\\u0026"),
            '\u{2028}' => out.extend_from_slice(b"\\u2028"),
            '\u{2029}' => out.extend_from_slice(b"\\u2029"),
            _ => {
                let mut buf = [0; 4];
                out.extend_from_slice(character.encode_utf8(&mut buf).as_bytes());
            }
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
    let normalized = normalize_protocol_field_name(name);
    [
        "api_key",
        "api_secret_key",
        "password",
        "authorization",
        "authorization_header",
        "bearer_token",
        "access_token",
        "refresh_token",
        "api_token",
        "client_secret",
        "cookie",
        "set_cookie",
        "raw_credential",
        "credential_value",
        "secret",
        "token",
        "raw_provider_request",
        "raw_provider_response",
        "raw_provider_error",
        "raw_provider_http_request_body",
        "raw_provider_http_response_body",
        "raw_provider_error_body",
        "raw_provider_payload",
        "provider_payload",
        "provider_request_body",
        "provider_response_body",
        "provider_error_body",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn normalize_protocol_field_name(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut normalized = String::new();
    let mut wrote_separator = false;
    for (index, current) in chars.iter().copied().enumerate() {
        if matches!(current, '-' | ' ' | '.' | '/') {
            if !normalized.is_empty() && !wrote_separator {
                normalized.push('_');
                wrote_separator = true;
            }
            continue;
        }
        let previous = index.checked_sub(1).and_then(|idx| chars.get(idx)).copied();
        let next = chars.get(index + 1).copied();
        if index > 0
            && current.is_ascii_uppercase()
            && !wrote_separator
            && previous.is_some_and(|value| {
                value.is_ascii_lowercase()
                    || value.is_ascii_digit()
                    || (value.is_ascii_uppercase()
                        && next.is_some_and(|next| next.is_ascii_lowercase()))
            })
        {
            normalized.push('_');
        }
        for lower in current.to_lowercase() {
            normalized.push(lower);
        }
        wrote_separator = false;
    }
    normalized.trim_matches('_').to_owned()
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

fn is_sha256_hex(value: &str) -> bool {
    let value = value.trim();
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn authenticated_promotion_receipt(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("sig:") || value.starts_with("auth:")
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

        for (field, mutate) in [
            (
                "tenant_id",
                (|envelope: &mut SourceRuntimeEnvelope| envelope.tenant_id.clear())
                    as fn(&mut SourceRuntimeEnvelope),
            ),
            (
                "runtime_id",
                (|envelope: &mut SourceRuntimeEnvelope| envelope.runtime_id.clear())
                    as fn(&mut SourceRuntimeEnvelope),
            ),
            (
                "source_id",
                (|envelope: &mut SourceRuntimeEnvelope| envelope.source_id.clear())
                    as fn(&mut SourceRuntimeEnvelope),
            ),
            (
                "family_id",
                (|envelope: &mut SourceRuntimeEnvelope| envelope.family_id.clear())
                    as fn(&mut SourceRuntimeEnvelope),
            ),
            (
                "attempt_id",
                (|envelope: &mut SourceRuntimeEnvelope| envelope.attempt_id.clear())
                    as fn(&mut SourceRuntimeEnvelope),
            ),
        ] {
            let mut envelope = fixture_envelope(SourceRuntimeOperation::ReadPage);
            mutate(&mut envelope);
            assert_eq!(
                validate_envelope(&envelope),
                Err(ProtocolError::MissingIdentity(field))
            );
        }

        for operation in ["Sync", "Commit"] {
            let mut envelope =
                serde_json::to_value(fixture_envelope(SourceRuntimeOperation::ReadPage)).unwrap();
            envelope["operation"] = serde_json::Value::String(operation.to_owned());
            assert!(matches!(
                validate_envelope_json(&envelope),
                Err(ProtocolError::UnsupportedOperation(found)) if found == operation
            ));
        }

        for &field in raw_secret_sentinel_field_names() {
            for surface in ["public_config", "result", "error"] {
                let mut envelope = fixture_envelope(SourceRuntimeOperation::ReadPage);
                match surface {
                    "public_config" => {
                        envelope
                            .public_config
                            .insert(field.to_owned(), "sentinel".to_owned());
                    }
                    "result" => {
                        envelope.result = Some(SourceRuntimeResult {
                            events_scanned: 1,
                            events_accepted: 0,
                            next_cursor: String::new(),
                            diagnostics: BTreeMap::from([(
                                field.to_owned(),
                                "sentinel".to_owned(),
                            )]),
                        });
                    }
                    "error" => {
                        envelope.error = Some(SourceRuntimeErrorShape {
                            code: "provider_error".to_owned(),
                            category: "provider".to_owned(),
                            retryable: true,
                            diagnostics: BTreeMap::from([(
                                field.to_owned(),
                                "sentinel".to_owned(),
                            )]),
                        });
                    }
                    _ => unreachable!(),
                }
                assert!(
                    matches!(
                        validate_envelope(&envelope),
                        Err(ProtocolError::RawSecretField(_))
                    ),
                    "{surface}.{field} accepted"
                );
            }
        }

        for field in [
            "apiKey",
            "API-SECRET-KEY",
            "Authorization",
            "bearerToken",
            "access-token",
            "setCookie",
            "rawProviderRequest",
            "providerResponseBody",
            "provider-error-body",
        ] {
            let mut envelope = fixture_envelope(SourceRuntimeOperation::ReadPage);
            envelope
                .public_config
                .insert(field.to_owned(), "sentinel".to_owned());
            assert!(
                matches!(
                    validate_envelope(&envelope),
                    Err(ProtocolError::RawSecretField(_))
                ),
                "{field} accepted"
            );
        }
        println!(
            "source_runtime_protocol_contract accepted=DescribePlan,Check,Discover,ReadPage rejected=unknown_revision,missing_tenant,missing_runtime,missing_source,missing_family,missing_attempt,worker_sync_rejected,unknown_operation,raw_secret raw_secret_fields=[]"
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
            promotion_receipt: "sig:promotion:test".to_owned(),
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

    #[test]
    fn authority_evidence_rejects_malformed_digest_and_unsigned_promotion_receipt() {
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
            promotion_receipt: "sig:promotion:test".to_owned(),
        };
        let mut bad_digest = complete.clone();
        bad_digest.plan_digest = "not-a-sha256".to_owned();
        assert_eq!(
            validate_authority_evidence(&bad_digest),
            Err(ProtocolError::InvalidAuthorityDigest(
                "compiled_plan_digest"
            ))
        );

        let mut unsigned = complete;
        unsigned.promotion_receipt = "promotion:test".to_owned();
        assert_eq!(
            validate_authority_evidence(&unsigned),
            Err(ProtocolError::UnauthenticatedPromotionReceipt)
        );
    }

    fn raw_secret_sentinel_field_names() -> &'static [&'static str] {
        &[
            "api_key",
            "api_secret_key",
            "password",
            "authorization",
            "bearer_token",
            "access_token",
            "refresh_token",
            "api_token",
            "client_secret",
            "cookie",
            "set_cookie",
            "raw_provider_request",
            "raw_provider_response",
            "raw_provider_error",
            "raw_provider_payload",
            "provider_payload",
            "provider_request_body",
            "provider_response_body",
            "provider_error_body",
        ]
    }
}
