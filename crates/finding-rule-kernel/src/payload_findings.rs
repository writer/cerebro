//! Rule-specific payload authority staged behind the shared finding DTO seam.
//!
//! This module is intentionally not registered by `lib.rs` yet. The active
//! shared authority lane owns dispatcher, wire-model, and Wasm artifact paths.
//! Its source-only integration test imports this file directly until that seam
//! is published and this module can use the shared `FindingRecord` verbatim.

#[path = "payload_findings/aurelius.rs"]
mod aurelius;
#[path = "payload_findings/cosmo.rs"]
mod cosmo;
#[path = "payload_findings/model.rs"]
mod model;

pub(crate) use model::{
    Action, CompleteFindingRecord, Decision, EvaluatorOutput, EvaluatorReceipt, EventInput,
    HostFindingFields, KernelError, MAX_PAYLOAD_ARRAY_ITEMS, MAX_PAYLOAD_BYTES, MAX_PAYLOAD_DEPTH,
    MAX_PAYLOAD_OBJECT_FIELDS, MAX_PAYLOAD_STRING_BYTES, Operation, PersistencePath,
    RuleFindingDecision, RuleRequest, ScopedDecision, ScopedPersistenceAction, TrustedRuntime,
};

/// Evaluates one of the two closed payload-backed rule families.
pub(crate) fn evaluate(request: &RuleRequest) -> Result<Decision, KernelError> {
    match request.rule_id.trim() {
        aurelius::RULE_ID => aurelius::evaluate(request),
        cosmo::RULE_ID => cosmo::evaluate(request),
        _ => Err(KernelError::UnsupportedRule),
    }
}

/// Runs exactly one evaluator and attaches the trusted storage workspace.
///
/// The evaluator is injected so the host boundary can prove that a Wasm
/// invocation failure is terminal: this function never calls a second engine.
pub(crate) fn evaluate_scoped_with(
    request: &RuleRequest,
    evaluator: impl FnOnce(&RuleRequest) -> Result<Decision, KernelError>,
) -> Result<ScopedDecision, KernelError> {
    evaluate_scoped_output_with(request, |request| {
        let decision = evaluator(request)?;
        Ok(EvaluatorOutput {
            receipt: expected_receipt(request, &decision)?,
            decision,
        })
    })
}

pub(crate) fn evaluate_scoped_output_with(
    request: &RuleRequest,
    evaluator: impl FnOnce(&RuleRequest) -> Result<EvaluatorOutput, KernelError>,
) -> Result<ScopedDecision, KernelError> {
    if request.runtime.workspace_id.trim().is_empty() {
        return Err(KernelError::MissingTrustedContext);
    }
    let output = evaluator(request)?;
    validate_evaluator_receipt(request, &output)?;
    let decision = output.decision;
    validate_evaluator_decision(request, &decision)?;
    Ok(ScopedDecision {
        workspace_id: request.runtime.workspace_id.trim().to_owned(),
        tenant_id: request.runtime.tenant_id.trim().to_owned(),
        runtime_id: request.runtime.runtime_id.trim().to_owned(),
        source_id: request.runtime.source_id.trim().to_owned(),
        rule_id: request.rule_id.trim().to_owned(),
        event_id: request.event.id.trim().to_owned(),
        observed_at: model::normalized_observation_time(&request.event.observed_at)?,
        replay_sequence: request.event.replay_sequence,
        decision,
    })
}

fn expected_receipt(
    request: &RuleRequest,
    decision: &Decision,
) -> Result<EvaluatorReceipt, KernelError> {
    let output =
        serde_json::to_vec(decision).map_err(|_| KernelError::MalformedEvaluatorResponse)?;
    let mut input = Vec::new();
    for part in [
        request.rule_id.trim(),
        request.runtime.workspace_id.trim(),
        request.runtime.tenant_id.trim(),
        request.runtime.runtime_id.trim(),
        request.runtime.source_id.trim(),
        request.event.id.trim(),
        request.event.tenant_id.trim(),
        request.event.source_id.trim(),
        request.event.kind.trim(),
        request.event.schema_ref.trim(),
        request.event.observed_at.trim(),
    ] {
        input.extend_from_slice(part.as_bytes());
        input.push(0);
    }
    input.extend_from_slice(&request.event.replay_sequence.to_be_bytes());
    for (key, value) in &request.event.attributes {
        input.extend_from_slice(key.as_bytes());
        input.push(0);
        input.extend_from_slice(value.as_bytes());
        input.push(0);
    }
    input.extend_from_slice(&request.event.payload);
    Ok(EvaluatorReceipt {
        workspace_id: request.runtime.workspace_id.trim().into(),
        tenant_id: request.runtime.tenant_id.trim().into(),
        runtime_id: request.runtime.runtime_id.trim().into(),
        source_id: request.runtime.source_id.trim().into(),
        rule_id: request.rule_id.trim().into(),
        definition_digest: match request.rule_id.trim() {
            aurelius::RULE_ID => aurelius::DEFINITION_DIGEST,
            cosmo::RULE_ID => cosmo::DEFINITION_DIGEST,
            _ => return Err(KernelError::UnsupportedRule),
        }
        .into(),
        input_digest: model::byte_digest(&input),
        output_digest: model::byte_digest(&output),
        action: decision.action,
    })
}

fn validate_evaluator_receipt(
    request: &RuleRequest,
    output: &EvaluatorOutput,
) -> Result<(), KernelError> {
    let expected = expected_receipt(request, &output.decision)?;
    if output.receipt != expected {
        return Err(KernelError::InvalidEvaluatorReceipt);
    }
    Ok(())
}

fn validate_evaluator_decision(
    request: &RuleRequest,
    decision: &Decision,
) -> Result<(), KernelError> {
    let structural = match decision.action {
        Action::None => decision.anchor.is_empty() && decision.finding.is_none(),
        Action::Open => decision.anchor.is_empty() && decision.finding.is_some(),
        Action::Close | Action::OpenAnchor => {
            !decision.anchor.trim().is_empty() && decision.finding.is_none()
        }
    };
    if !structural {
        return Err(KernelError::MalformedEvaluatorResponse);
    }
    let allowed = match request.operation {
        Operation::Evaluate => matches!(decision.action, Action::None | Action::Open),
        Operation::OpenAnchor => matches!(decision.action, Action::None | Action::OpenAnchor),
        Operation::Close => matches!(decision.action, Action::None | Action::Close),
    };
    if !allowed {
        return Err(KernelError::MalformedEvaluatorResponse);
    }
    if let Some(finding) = &decision.finding
        && (finding.tenant_id != request.runtime.tenant_id.trim()
            || finding.runtime_id != request.runtime.runtime_id.trim()
            || finding.rule_id != request.rule_id.trim()
            || finding.id.trim().is_empty()
            || finding.fingerprint.trim().is_empty()
            || finding.id != finding.fingerprint)
    {
        return Err(KernelError::InvalidEvaluatorReceipt);
    }
    Ok(())
}

/// Production rule dispatch through the closed, workspace-scoped envelope.
pub(crate) fn evaluate_scoped(request: &RuleRequest) -> Result<ScopedDecision, KernelError> {
    evaluate_scoped_with(request, evaluate)
}

#[cfg(test)]
#[path = "payload_findings/tests.rs"]
mod tests;
