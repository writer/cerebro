use prost::Message;
use sha2::{Digest, Sha256};

use super::{
    contract::{
        MAX_CONTEXT_IDENTIFIER_BYTES, canonical_plan_digest, canonical_result_digest, lower_sha256,
        validate_and_deduplicate_records, validate_cursor, validate_execution_context,
    },
    error::SourceExecutionError,
    wire::{
        SourceExecutionContextRequestV1, SourceExecutionLifecycleDecisionV1,
        SourceExecutionLifecycleRequestV1, SourceExecutionPhaseV1, SourceExecutionPlanV1,
        SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1, SourceWorkerRecordV1,
        SourceWorkerSafeReceiptV1,
    },
};

/// Constructs a trusted, retry-stable context for one logical provider page.
pub fn build_execution_context(
    request: &SourceExecutionContextRequestV1,
) -> Result<SourceWorkerExecutionContextV1, SourceExecutionError> {
    validate_context_request(request)?;
    let logical_page_id = logical_page_id(request);
    let context = SourceWorkerExecutionContextV1 {
        tenant_id: request.tenant_id.clone(),
        runtime_id: request.runtime_id.clone(),
        logical_page_id,
        prior_cursor: request.prior_cursor.clone(),
        runtime_generation: request.runtime_generation,
        lease_generation: request.lease_generation,
        observed_at_unix_millis: request.observed_at_unix_millis,
    };
    validate_execution_context(&context)?;
    Ok(context)
}

/// Advances a fenced page through exactly one durable lifecycle phase.
pub fn transition_lifecycle(
    request: &SourceExecutionLifecycleRequestV1,
) -> Result<SourceExecutionLifecycleDecisionV1, SourceExecutionError> {
    let plan = request
        .plan
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    let context = request
        .context
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    let receipt = request
        .receipt
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    let result = request
        .result
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;

    validate_lifecycle_inputs(plan, context, receipt, result)?;
    if request.current_lease_generation != context.lease_generation {
        return Err(SourceExecutionError::LeaseLost);
    }

    let completed_phase = SourceExecutionPhaseV1::try_from(request.completed_phase)
        .map_err(|_| SourceExecutionError::InternalRuntime)?;
    let required_phase = match completed_phase {
        SourceExecutionPhaseV1::Decoded => SourceExecutionPhaseV1::Appended,
        SourceExecutionPhaseV1::Appended => SourceExecutionPhaseV1::Projected,
        SourceExecutionPhaseV1::Projected => SourceExecutionPhaseV1::Checkpointed,
        SourceExecutionPhaseV1::Checkpointed => SourceExecutionPhaseV1::Complete,
        SourceExecutionPhaseV1::Unspecified | SourceExecutionPhaseV1::Complete => {
            return Err(SourceExecutionError::InternalRuntime);
        }
    };

    if completed_phase == SourceExecutionPhaseV1::Decoded {
        if !request.prior_transition_digest_sha256.is_empty() {
            return Err(SourceExecutionError::InvalidDigest);
        }
    } else {
        let expected = transition_digest(plan, context, result, completed_phase);
        if request.prior_transition_digest_sha256 != expected {
            return Err(SourceExecutionError::InvalidDigest);
        }
    }

    let records = admit_records(plan, context, &result.records)?;
    let (checkpoint_cursor, checkpoint_watermark_unix_millis) = if required_phase
        == SourceExecutionPhaseV1::Checkpointed
        || required_phase == SourceExecutionPhaseV1::Complete
    {
        (
            result.next_cursor.clone(),
            records
                .iter()
                .map(|record| record.occurred_at_unix_millis)
                .max()
                .unwrap_or(context.observed_at_unix_millis),
        )
    } else {
        (String::new(), 0)
    };

    Ok(SourceExecutionLifecycleDecisionV1 {
        required_phase: required_phase as i32,
        transition_digest_sha256: transition_digest(plan, context, result, required_phase),
        admitted_records: if required_phase == SourceExecutionPhaseV1::Appended {
            records
        } else {
            Vec::new()
        },
        checkpoint_cursor,
        checkpoint_watermark_unix_millis,
    })
}

pub(super) fn context_bytes(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    let request = SourceExecutionContextRequestV1::decode(input)
        .map_err(|_| SourceExecutionError::Protobuf)?;
    Ok(build_execution_context(&request)?.encode_to_vec())
}

pub(super) fn transition_bytes(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    let request = SourceExecutionLifecycleRequestV1::decode(input)
        .map_err(|_| SourceExecutionError::Protobuf)?;
    Ok(transition_lifecycle(&request)?.encode_to_vec())
}

fn validate_context_request(
    request: &SourceExecutionContextRequestV1,
) -> Result<(), SourceExecutionError> {
    if request.tenant_id.trim().is_empty()
        || request.tenant_id.len() > MAX_CONTEXT_IDENTIFIER_BYTES
        || request.tenant_id.chars().any(char::is_control)
        || !safe_identifier(&request.runtime_id)
        || request.page_number == 0
        || request.runtime_generation == 0
        || request.lease_generation == 0
        || request.observed_at_unix_millis <= 0
    {
        return Err(SourceExecutionError::InvalidExecutionContext);
    }
    validate_cursor(&request.prior_cursor)
}

fn validate_lifecycle_inputs(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    receipt: &SourceWorkerSafeReceiptV1,
    result: &SourceWorkerDecodeResultV1,
) -> Result<(), SourceExecutionError> {
    validate_execution_context(context)?;
    if !lower_sha256(&plan.plan_digest_sha256)
        || canonical_plan_digest(plan) != plan.plan_digest_sha256
        || result.plan_id != plan.plan_id
        || result.plan_digest_sha256 != plan.plan_digest_sha256
    {
        return Err(SourceExecutionError::InvalidPlan);
    }
    if receipt.tenant_id != context.tenant_id
        || receipt.runtime_id != context.runtime_id
        || result.tenant_id != context.tenant_id
        || result.runtime_id != context.runtime_id
    {
        return Err(SourceExecutionError::TenantMismatch);
    }
    if receipt.runtime_generation != context.runtime_generation
        || receipt.lease_generation != context.lease_generation
        || result.runtime_generation != context.runtime_generation
        || result.lease_generation != context.lease_generation
    {
        return Err(SourceExecutionError::StaleGeneration);
    }
    if receipt.logical_page_id != context.logical_page_id
        || result.logical_page_id != context.logical_page_id
        || receipt.observed_at_unix_millis != context.observed_at_unix_millis
        || result.observed_at_unix_millis != context.observed_at_unix_millis
        || receipt.request_intent_digest != result.request_intent_digest
        || receipt.plan_digest_sha256 != plan.plan_digest_sha256
    {
        return Err(SourceExecutionError::MissingExecutionIdentity);
    }
    if !lower_sha256(&receipt.request_intent_digest)
        || !lower_sha256(&receipt.response_sha256)
        || !lower_sha256(&result.result_digest_sha256)
        || result.result_digest_sha256
            != canonical_result_digest(receipt, &result.next_cursor, &result.records)?
    {
        return Err(SourceExecutionError::InvalidDigest);
    }
    validate_cursor(&result.next_cursor)
}

fn admit_records(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    records: &[SourceWorkerRecordV1],
) -> Result<Vec<SourceWorkerRecordV1>, SourceExecutionError> {
    let mut records = validate_and_deduplicate_records(records.to_vec())?;
    for record in &mut records {
        if record
            .attributes
            .get("tenant_id")
            .is_some_and(|tenant_id| tenant_id != &context.tenant_id)
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        if plan.required_attributes.iter().any(|required| {
            record
                .attributes
                .get(required)
                .is_none_or(|value| value.trim().is_empty())
        }) {
            return Err(SourceExecutionError::EventContractRejected);
        }
        let payload = serde_json::from_slice::<serde_json::Value>(&record.payload_json)
            .map_err(|_| SourceExecutionError::MalformedResponse)?;
        if plan
            .required_payload_fields
            .iter()
            .any(|required| payload.get(required).is_none_or(serde_json::Value::is_null))
        {
            return Err(SourceExecutionError::EventContractRejected);
        }
        if plan.source_id == "azure" && plan.family_id == "authorization_policy" {
            record
                .attributes
                .insert("domain".to_owned(), context.tenant_id.clone());
            record.payload_json = serde_json::to_vec(&serde_json::json!({
                "id": record.provider_id,
                "tenant_id": context.tenant_id,
                "raw": payload,
            }))
            .map_err(|_| SourceExecutionError::InternalRuntime)?;
        }
    }
    Ok(records)
}

fn logical_page_id(request: &SourceExecutionContextRequestV1) -> String {
    let mut hasher = Sha256::new();
    for value in [
        request.tenant_id.as_bytes(),
        request.runtime_id.as_bytes(),
        &request.runtime_generation.to_be_bytes(),
        &request.page_number.to_be_bytes(),
        request.prior_cursor.as_bytes(),
    ] {
        update_length_prefixed(&mut hasher, value);
    }
    format!("source-page-v1:{}", hex_bytes(&hasher.finalize()))
}

fn transition_digest(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    result: &SourceWorkerDecodeResultV1,
    phase: SourceExecutionPhaseV1,
) -> String {
    let mut hasher = Sha256::new();
    for value in [
        b"source-execution-transition-v1".as_slice(),
        plan.plan_digest_sha256.as_bytes(),
        context.tenant_id.as_bytes(),
        context.runtime_id.as_bytes(),
        context.logical_page_id.as_bytes(),
        result.result_digest_sha256.as_bytes(),
        &(phase as i32).to_be_bytes(),
    ] {
        update_length_prefixed(&mut hasher, value);
    }
    update_length_prefixed(&mut hasher, &context.runtime_generation.to_be_bytes());
    update_length_prefixed(&mut hasher, &context.lease_generation.to_be_bytes());
    hex_bytes(&hasher.finalize())
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONTEXT_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_bytes(value: &[u8]) -> String {
    use std::fmt::Write as _;

    value.iter().fold(
        String::with_capacity(value.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn context_request(lease_generation: u64) -> SourceExecutionContextRequestV1 {
        SourceExecutionContextRequestV1 {
            tenant_id: "tenant-a".into(),
            runtime_id: "runtime-a".into(),
            prior_cursor: "cursor-1".into(),
            page_number: 2,
            runtime_generation: 4,
            lease_generation,
            observed_at_unix_millis: 1_725_000_000_000,
        }
    }

    fn lifecycle_request() -> SourceExecutionLifecycleRequestV1 {
        let context = build_execution_context(&context_request(9)).expect("valid context");
        let mut plan = SourceExecutionPlanV1 {
            plan_id: "source-plan-v1:test:widgets".into(),
            source_id: "test".into(),
            family_id: "widgets".into(),
            provider_kernel: "test.widgets".into(),
            method: "GET".into(),
            origin: "https://example.test".into(),
            path: "/widgets".into(),
            record_selector: "$.value".into(),
            id_field: "id".into(),
            singleton_fallback_id: String::new(),
            max_response_bytes: 1024,
            event_kind: "test.widget".into(),
            schema_ref: "test/widget/v1".into(),
            required_attributes: vec!["family".into()],
            required_payload_fields: vec!["id".into()],
            plan_digest_sha256: String::new(),
        };
        plan.plan_digest_sha256 = canonical_plan_digest(&plan);
        let receipt = SourceWorkerSafeReceiptV1 {
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: "1".repeat(64),
            runtime_generation: context.runtime_generation,
            lease_generation: context.lease_generation,
            credential_operation: "test.widgets.read".into(),
            status_code: 200,
            response_bytes: 24,
            response_sha256: "2".repeat(64),
            tenant_id: context.tenant_id.clone(),
            runtime_id: context.runtime_id.clone(),
            observed_at_unix_millis: context.observed_at_unix_millis,
        };
        let records = vec![SourceWorkerRecordV1 {
            provider_id: "widget-1".into(),
            attributes: HashMap::from([
                ("family".into(), "widgets".into()),
                ("tenant_id".into(), context.tenant_id.clone()),
            ]),
            payload_json: br#"{"id":"widget-1"}"#.to_vec(),
            event_id: "test.widgets.tenant-a.widget-1".into(),
            occurred_at_unix_millis: context.observed_at_unix_millis,
        }];
        let mut result = SourceWorkerDecodeResultV1 {
            plan_id: plan.plan_id.clone(),
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: receipt.request_intent_digest.clone(),
            records,
            next_cursor: "cursor-2".into(),
            result_digest_sha256: String::new(),
            tenant_id: context.tenant_id.clone(),
            runtime_id: context.runtime_id.clone(),
            runtime_generation: context.runtime_generation,
            lease_generation: context.lease_generation,
            observed_at_unix_millis: context.observed_at_unix_millis,
        };
        result.result_digest_sha256 =
            canonical_result_digest(&receipt, &result.next_cursor, &result.records)
                .expect("valid result digest");
        SourceExecutionLifecycleRequestV1 {
            plan: Some(plan),
            context: Some(context),
            receipt: Some(receipt),
            result: Some(result),
            completed_phase: SourceExecutionPhaseV1::Decoded as i32,
            prior_transition_digest_sha256: String::new(),
            current_lease_generation: 9,
        }
    }

    #[test]
    fn logical_page_identity_is_stable_across_lease_turnover_and_tenant_scoped() {
        let first = build_execution_context(&context_request(9)).expect("first context");
        let resumed = build_execution_context(&context_request(10)).expect("resumed context");
        assert_eq!(first.logical_page_id, resumed.logical_page_id);

        let mut other_tenant = context_request(9);
        other_tenant.tenant_id = "tenant-b".into();
        let other = build_execution_context(&other_tenant).expect("other tenant context");
        assert_ne!(first.logical_page_id, other.logical_page_id);
    }

    #[test]
    fn rust_owns_the_append_projection_checkpoint_sequence() {
        let mut request = lifecycle_request();
        let append = transition_lifecycle(&request).expect("append decision");
        assert_eq!(
            append.required_phase,
            SourceExecutionPhaseV1::Appended as i32
        );
        assert_eq!(append.admitted_records.len(), 1);
        assert!(append.checkpoint_cursor.is_empty());

        request.completed_phase = SourceExecutionPhaseV1::Appended as i32;
        request.prior_transition_digest_sha256 = append.transition_digest_sha256;
        let project = transition_lifecycle(&request).expect("projection decision");
        assert_eq!(
            project.required_phase,
            SourceExecutionPhaseV1::Projected as i32
        );
        assert!(project.checkpoint_cursor.is_empty());

        request.completed_phase = SourceExecutionPhaseV1::Projected as i32;
        request.prior_transition_digest_sha256 = project.transition_digest_sha256;
        let checkpoint = transition_lifecycle(&request).expect("checkpoint decision");
        assert_eq!(
            checkpoint.required_phase,
            SourceExecutionPhaseV1::Checkpointed as i32
        );
        assert_eq!(checkpoint.checkpoint_cursor, "cursor-2");

        request.completed_phase = SourceExecutionPhaseV1::Checkpointed as i32;
        request.prior_transition_digest_sha256 = checkpoint.transition_digest_sha256;
        let complete = transition_lifecycle(&request).expect("completion decision");
        assert_eq!(
            complete.required_phase,
            SourceExecutionPhaseV1::Complete as i32
        );
    }

    #[test]
    fn stale_lease_and_phase_digest_tampering_fail_closed() {
        let mut request = lifecycle_request();
        request.current_lease_generation = 10;
        assert_eq!(
            transition_lifecycle(&request),
            Err(SourceExecutionError::LeaseLost)
        );

        request.current_lease_generation = 9;
        request.completed_phase = SourceExecutionPhaseV1::Appended as i32;
        request.prior_transition_digest_sha256 = "3".repeat(64);
        assert_eq!(
            transition_lifecycle(&request),
            Err(SourceExecutionError::InvalidDigest)
        );
    }
}
