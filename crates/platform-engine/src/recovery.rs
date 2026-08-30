//! Deterministic aggregation of projection-recovery verification results.
//!
//! The engine orders caller-supplied checks, derives a conservative aggregate
//! state, and hashes the report. It does not execute checks, inspect stores,
//! establish authority, repair projections, or initiate replay.

use cerebro_platform_sdk::{
    ContentDigest, GraphRevision, RecoveryCheck, RecoveryReport, RecoveryState, SdkError, TenantId,
};

use crate::canonical;

/// Builds a content-addressed recovery report from completed checks.
///
/// Checks are stably sorted by name; duplicate names are retained in caller
/// order and all entries contribute to the digest. Names must be non-empty and
/// have no surrounding whitespace, but names, reason codes, and check count are
/// otherwise unbounded by this function.
///
/// Aggregate precedence is fail-closed: any `Failed` check makes the report
/// `Failed`. Otherwise, a Postgres/Neo4j revision mismatch or any
/// `Indeterminate` check makes it `Indeterminate`; only equal revisions and all
/// `Passed` checks produce `Passed`. Optional digest values are evidence only:
/// this function does not compare them or derive the individual check state.
///
/// The report digest covers tenant, append-log sequence, both revisions, sorted
/// checks, and the derived state. It does not prove that the supplied positions
/// were read consistently or that checks were executed against the named tenant.
///
/// # Errors
///
/// Returns [`SdkError::Empty`] when no checks are supplied,
/// [`SdkError::Invalid`] for an empty or padded check name, or
/// [`SdkError::Backend`] if canonical report serialization fails.
pub fn build_recovery_report(
    tenant_id: TenantId,
    append_log_sequence: u64,
    postgres_revision: GraphRevision,
    neo4j_revision: GraphRevision,
    mut checks: Vec<RecoveryCheck>,
) -> Result<RecoveryReport, SdkError> {
    if checks.is_empty() {
        return Err(SdkError::Empty("recovery checks"));
    }

    // Stable sorting makes distinct names independent of collection order while
    // retaining caller order for duplicate names that the contract permits.
    checks.sort_by(|left, right| left.name.cmp(&right.name));
    if checks
        .iter()
        .any(|check| check.name.is_empty() || check.name.trim() != check.name)
    {
        return Err(SdkError::Invalid("recovery check name"));
    }
    // A definite failed invariant outranks uncertainty. Projection revision
    // disagreement is uncertainty unless a check already established failure.
    let state = if checks
        .iter()
        .any(|check| check.state == RecoveryState::Failed)
    {
        RecoveryState::Failed
    } else if postgres_revision != neo4j_revision
        || checks
            .iter()
            .any(|check| check.state == RecoveryState::Indeterminate)
    {
        RecoveryState::Indeterminate
    } else {
        RecoveryState::Passed
    };
    let report_digest: ContentDigest = canonical::digest(&(
        &tenant_id,
        append_log_sequence,
        postgres_revision,
        neo4j_revision,
        &checks,
        state,
    ))?;
    Ok(RecoveryReport {
        tenant_id,
        append_log_sequence,
        postgres_revision,
        neo4j_revision,
        checks,
        state,
        report_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatched_projection_revisions_make_an_otherwise_passing_report_indeterminate() {
        let report = build_recovery_report(
            TenantId::parse("tenant-a").unwrap(),
            7,
            GraphRevision::new(3).unwrap(),
            GraphRevision::new(4).unwrap(),
            vec![RecoveryCheck {
                name: "append log".to_owned(),
                state: RecoveryState::Passed,
                expected_digest: Some(ContentDigest::of_bytes("expected")),
                observed_digest: Some(ContentDigest::of_bytes("expected")),
                reason_code: None,
            }],
        )
        .unwrap();

        assert_eq!(report.state, RecoveryState::Indeterminate);
    }
}
