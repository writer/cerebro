use cerebro_platform_sdk::{
    ContentDigest, GraphRevision, RecoveryCheck, RecoveryReport, RecoveryState, SdkError, TenantId,
};

use crate::canonical;

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
    checks.sort_by(|left, right| left.name.cmp(&right.name));
    if checks
        .iter()
        .any(|check| check.name.is_empty() || check.name.trim() != check.name)
    {
        return Err(SdkError::Invalid("recovery check name"));
    }
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
