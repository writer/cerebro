use cerebro_platform_sdk::{
    AssertionId, EntityId, EvidenceQuality, EvidenceReference, GraphRevision,
    ProvenanceExplanation, SdkError, TenantId,
};

use crate::canonical;

pub fn assemble_provenance(
    tenant_id: TenantId,
    graph_revision: GraphRevision,
    entity_id: Option<EntityId>,
    assertion_id: Option<AssertionId>,
    mut evidence: Vec<EvidenceReference>,
    quality: EvidenceQuality,
) -> Result<ProvenanceExplanation, SdkError> {
    evidence.sort_by(|left, right| {
        left.evidence_id
            .cmp(&right.evidence_id)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let explanation_digest = canonical::digest(&(
        &tenant_id,
        graph_revision,
        &entity_id,
        &assertion_id,
        &evidence,
        &quality,
    ))?;
    let explanation = ProvenanceExplanation {
        tenant_id,
        graph_revision,
        entity_id,
        assertion_id,
        evidence,
        quality,
        explanation_digest,
    };
    explanation.validate()?;
    Ok(explanation)
}
