//! Deterministic assembly of bounded provenance explanations.
//!
//! The engine owns evidence ordering and content-digest construction. It does
//! not fetch evidence, authenticate source events, assess the quality vector,
//! or authorize the resulting explanation for disclosure.

use cerebro_platform_sdk::{
    AssertionId, EntityId, EvidenceQuality, EvidenceReference, GraphRevision,
    ProvenanceExplanation, SdkError, TenantId,
};

use crate::canonical;

/// Orders evidence, binds it to one graph target, and computes an explanation digest.
///
/// Evidence is sorted by evidence identity and then event identity before
/// hashing. References with identical sort keys are retained rather than
/// deduplicated, so callers remain responsible for duplicate-admission policy.
/// The digest covers tenant, graph revision, both optional target fields, the
/// ordered evidence records, and the complete quality vector.
///
/// # Errors
///
/// Returns [`SdkError::Backend`] if canonical serialization fails, or the
/// shape error from [`ProvenanceExplanation::validate`] when the request does
/// not name exactly one target or supplies an invalid evidence count.
pub fn assemble_provenance(
    tenant_id: TenantId,
    graph_revision: GraphRevision,
    entity_id: Option<EntityId>,
    assertion_id: Option<AssertionId>,
    mut evidence: Vec<EvidenceReference>,
    quality: EvidenceQuality,
) -> Result<ProvenanceExplanation, SdkError> {
    // Canonicalize caller-controlled collection order before hashing so normal
    // source pagination order does not change an otherwise identical receipt.
    evidence.sort_by(|left, right| {
        left.evidence_id
            .cmp(&right.evidence_id)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    // Hash the semantic material before constructing the public receipt; the
    // stored digest is not recursively included in its own content address.
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

#[cfg(test)]
mod tests {
    use cerebro_platform_sdk::{EntityId, GraphRevision};

    use super::*;

    #[test]
    fn provenance_requires_at_least_one_evidence_reference() {
        let quality = EvidenceQuality::new(100, 100, 100, 100, 100, false).unwrap();
        assert_eq!(
            assemble_provenance(
                TenantId::parse("tenant-a").unwrap(),
                GraphRevision::new(1).unwrap(),
                Some(EntityId::parse("repository:one").unwrap()),
                None,
                Vec::new(),
                quality,
            ),
            Err(SdkError::Empty("provenance evidence"))
        );
    }
}
