use std::{collections::BTreeMap, path::Path};

use cerebro_organizational_model::{SourceRuntimeId, TenantId};
use cerebro_source_catalog::CompiledSource;
use cerebro_source_runtime_next::{
    CredentialLeaseReference, EgressPolicy, EgressRequestContext, HttpProviderAccess,
    HttpSourceConnector, OperationScopedCredentialLease, ResolvedAuth, SourceRuntimeOperation,
};

pub fn repository_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

pub fn qdrant_connector(
    source: CompiledSource,
    tenant: &TenantId,
    runtime_id: &SourceRuntimeId,
    base_url: &str,
    generation: u64,
) -> HttpSourceConnector {
    let request_intent_digest = "b".repeat(64);
    let context = EgressRequestContext {
        tenant_id: tenant.as_str().to_owned(),
        runtime_id: runtime_id.as_str().to_owned(),
        source_id: "qdrant_cloud".to_owned(),
        family_id: "clusters".to_owned(),
        operation: SourceRuntimeOperation::ReadPage,
        request_intent_digest: request_intent_digest.clone(),
        logical_page_id: format!("qdrant-clusters-{generation}"),
        source_generation: generation,
        authority_epoch: 1,
    };
    let credential_lease = OperationScopedCredentialLease::new(
        CredentialLeaseReference::new(
            format!("qdrant-clusters-lease-{generation}"),
            context.lease_scope().unwrap(),
            1_000,
            1_000,
        )
        .unwrap(),
    );
    let policy = EgressPolicy::live(
        tenant.as_str(),
        "clusters",
        &request_intent_digest,
        [base_url],
    )
    .unwrap();
    HttpSourceConnector::new(
        source,
        "clusters",
        base_url,
        BTreeMap::from([("account_id".to_owned(), "account-durable".to_owned())]),
        ResolvedAuth::Header {
            name: "Authorization".to_owned(),
            value: "apikey fixture-management-key".to_owned(),
        },
    )
    .unwrap()
    .with_provider_access(HttpProviderAccess::new_with_clock(
        context,
        policy,
        credential_lease,
        1_500,
    ))
}
