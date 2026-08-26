use std::{collections::BTreeMap, path::PathBuf};

use cerebro_organizational_graph::OrganizationalGraph;
use cerebro_source_catalog::{CompiledSource, SourceCatalog};

use crate::{
    CatalogGraphMapper, CredentialLeaseReference, EgressPolicy, EgressRequestContext,
    HttpProviderAccess, HttpSourceConnector, OperationScopedCredentialLease, ResolvedAuth,
    SourceRuntime, SourceRuntimeOperation,
};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

pub(super) fn qdrant_source() -> CompiledSource {
    let root = repository_root();
    SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap()
    .get("qdrant_cloud")
    .unwrap()
    .clone()
}

pub(super) fn qdrant_connector(
    source: &CompiledSource,
    family_id: &str,
    tenant_id: &str,
    runtime_id: &str,
    base_url: &str,
    generation: u64,
) -> HttpSourceConnector {
    let request_intent_digest = "a".repeat(64);
    let context = EgressRequestContext {
        tenant_id: tenant_id.to_owned(),
        runtime_id: runtime_id.to_owned(),
        source_id: "qdrant_cloud".to_owned(),
        family_id: family_id.to_owned(),
        operation: SourceRuntimeOperation::ReadPage,
        request_intent_digest: request_intent_digest.clone(),
        logical_page_id: format!("{family_id}-page-{generation}"),
        source_generation: generation,
        authority_epoch: 1,
    };
    let credential_lease = OperationScopedCredentialLease::new(
        CredentialLeaseReference::new(
            format!("qdrant-{family_id}-lease-{generation}"),
            context.lease_scope().unwrap(),
            1_000,
            1_000,
        )
        .unwrap(),
    );
    let egress_policy =
        EgressPolicy::live(tenant_id, family_id, &request_intent_digest, [base_url]).unwrap();
    let auth = ResolvedAuth::Header {
        name: "Authorization".to_owned(),
        value: "apikey fixture-management-key".to_owned(),
    };
    assert!(!format!("{auth:?}").contains("fixture-management-key"));
    HttpSourceConnector::new(
        source.clone(),
        family_id,
        base_url,
        BTreeMap::from([("account_id".to_owned(), "account-fixture".to_owned())]),
        auth,
    )
    .unwrap()
    .with_provider_access(HttpProviderAccess::new_with_clock(
        context,
        egress_policy,
        credential_lease,
        1_500,
    ))
}

pub(super) fn qdrant_runtime(
    source: &CompiledSource,
    family_id: &str,
    tenant_id: &str,
    runtime_id: &str,
    base_url: &str,
    generation: u64,
    store: OrganizationalGraph,
) -> SourceRuntime<HttpSourceConnector, CatalogGraphMapper, OrganizationalGraph> {
    let connector = qdrant_connector(
        source, family_id, tenant_id, runtime_id, base_url, generation,
    );
    let mapper = CatalogGraphMapper::new(source.clone(), "qdrant-cloud-v1").unwrap();
    SourceRuntime::new(connector, mapper, store)
}
