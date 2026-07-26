use cerebro_platform_sdk::{
    AssertionCondition, AssertionDefinition, AssertionEvaluation, AssertionState, ContentDigest,
    EvidenceQuality, FactQuery, GraphRevision, QueryResult, SdkError, TenantId,
};
use serde::Serialize;

use crate::canonical;

#[derive(Serialize)]
struct AssertionMaterial<'a> {
    tenant_id: &'a TenantId,
    name: &'a str,
    query: &'a FactQuery,
    condition: AssertionCondition,
    triggers: &'a [cerebro_platform_sdk::EvaluationTrigger],
    evidence_max_age_seconds: u64,
    enabled: bool,
}

pub fn assertion_definition_digest(
    definition: &AssertionDefinition,
) -> Result<ContentDigest, SdkError> {
    canonical::digest(&AssertionMaterial {
        tenant_id: &definition.tenant_id,
        name: &definition.name,
        query: &definition.query,
        condition: definition.condition,
        triggers: &definition.triggers,
        evidence_max_age_seconds: definition.evidence_max_age_seconds,
        enabled: definition.enabled,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledAssertion {
    definition: AssertionDefinition,
}

impl CompiledAssertion {
    pub fn definition(&self) -> &AssertionDefinition {
        &self.definition
    }
}

pub fn compile_assertion(definition: AssertionDefinition) -> Result<CompiledAssertion, SdkError> {
    definition.validate()?;
    if assertion_definition_digest(&definition)? != definition.definition_digest {
        return Err(SdkError::Invalid("assertion definition digest"));
    }
    Ok(CompiledAssertion { definition })
}

pub fn evaluate_assertion(
    compiled: &CompiledAssertion,
    result: &QueryResult,
    quality: &EvidenceQuality,
    evaluated_at_unix_millis: i64,
) -> Result<AssertionEvaluation, SdkError> {
    let definition = compiled.definition();
    if result.tenant_id != definition.tenant_id {
        return Err(SdkError::Invalid("assertion query tenant"));
    }
    let graph_revision = GraphRevision::new(result.graph_revision)?;
    if result.matches.len() > definition.query.limit() {
        return Err(SdkError::OutOfRange("assertion query matches"));
    }
    let matching_paths = u32::try_from(result.matches.len())
        .map_err(|_| SdkError::OutOfRange("assertion query matches"))?;
    let (state, reason_codes) = if !definition.enabled {
        (AssertionState::Indeterminate, vec!["assertion_disabled"])
    } else if result.truncated {
        (AssertionState::Indeterminate, vec!["query_truncated"])
    } else if quality.conflicting {
        (AssertionState::Indeterminate, vec!["evidence_conflicting"])
    } else if quality.minimum_score() == 0 {
        (AssertionState::Indeterminate, vec!["evidence_incomplete"])
    } else if definition.condition.evaluate(matching_paths) {
        (AssertionState::Satisfied, Vec::new())
    } else {
        (AssertionState::Violated, vec!["condition_not_met"])
    };
    let evidence_digest = canonical::digest(&(result, quality))?;
    Ok(AssertionEvaluation {
        assertion_id: definition.assertion_id.clone(),
        graph_revision,
        state,
        evaluated_at_unix_millis,
        matching_paths,
        reason_codes: reason_codes.into_iter().map(str::to_owned).collect(),
        evidence_digest,
    })
}
