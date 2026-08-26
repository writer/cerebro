mod admission_behavior_tests;
mod entity_conflict_tests;
mod identity_binding_tests;

use cerebro_organizational_model::{
    AssertionProvenance, CanonicalIdentity, CanonicalIdentityId, CollectionId, CompleteCollection,
    GraphAssertion, IdentityBindingAssertion, IdentityBindingState, IdentityClaim,
    IdentityResolutionMethod, ObservationId, ObservationRef, ProviderIdentity, ProviderKind,
    SourceRuntimeId,
};

use super::*;

fn identity_delta(
    provider_id: &str,
    canonical_id: &str,
    state: IdentityBindingState,
    claim: Option<IdentityClaim>,
) -> GraphDelta {
    identity_delta_with_method(
        provider_id,
        canonical_id,
        IdentityResolutionMethod::HumanDecision,
        state,
        claim,
    )
}

fn identity_delta_with_method(
    provider_id: &str,
    canonical_id: &str,
    method: IdentityResolutionMethod,
    state: IdentityBindingState,
    claim: Option<IdentityClaim>,
) -> GraphDelta {
    let tenant = TenantId::parse("tenant-a").unwrap();
    let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
    let collection = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse(format!("collection-{canonical_id}")).unwrap(),
        "okta.users",
        10,
    )
    .unwrap();
    let provider = ProviderIdentity::new(
        tenant.clone(),
        runtime,
        ProviderKind::parse("okta.user").unwrap(),
        provider_id,
        "Provider Person",
    )
    .unwrap();
    let canonical = CanonicalIdentity::new(
        tenant,
        CanonicalIdentityId::parse(canonical_id).unwrap(),
        "Canonical Person",
    )
    .unwrap();
    let provenance = AssertionProvenance::direct(
        vec![
            ObservationRef::new(
                collection.receipt(),
                ObservationId::parse(format!("observation-{canonical_id}")).unwrap(),
                format!("okta.user:{provider_id}"),
            )
            .unwrap(),
        ],
        "okta-identity-mapper",
        "v1",
    )
    .unwrap();
    let binding =
        IdentityBindingAssertion::new(&provider, &canonical, method, claim, state, provenance, 10)
            .unwrap();
    let mut builder = collection.begin_delta();
    builder.add_entity(provider.into_entity()).unwrap();
    builder.add_entity(canonical.into_entity()).unwrap();
    builder
        .add_assertion(GraphAssertion::IdentityBinding(binding))
        .unwrap();
    builder.build()
}

fn workforce_delta(employee_id: &str, email: &str) -> (GraphDelta, CanonicalIdentity) {
    let tenant = TenantId::parse("tenant-a").unwrap();
    let runtime = SourceRuntimeId::parse("okta-prod").unwrap();
    let collection = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse(format!("okta-{employee_id}")).unwrap(),
        "okta.users",
        10,
    )
    .unwrap();
    let provider = ProviderIdentity::new(
        tenant.clone(),
        runtime,
        ProviderKind::parse("okta.identity_user").unwrap(),
        "00u1",
        "Provider Person",
    )
    .unwrap();
    let employee_claim = IdentityClaim::employee_id(employee_id).unwrap();
    let canonical =
        CanonicalIdentity::for_claim(tenant, &employee_claim, "Canonical Person").unwrap();
    let provenance = AssertionProvenance::direct(
        vec![
            ObservationRef::new(
                collection.receipt(),
                ObservationId::parse(format!("observation-{employee_id}")).unwrap(),
                "okta.user:00u1",
            )
            .unwrap(),
        ],
        "okta-identity-mapper",
        "v1",
    )
    .unwrap();
    let employee_binding = IdentityBindingAssertion::new(
        &provider,
        &canonical,
        IdentityResolutionMethod::AuthoritativeEmployeeId,
        Some(employee_claim),
        IdentityBindingState::Confirmed,
        provenance.clone(),
        10,
    )
    .unwrap();
    let email_binding = IdentityBindingAssertion::new(
        &provider,
        &canonical,
        IdentityResolutionMethod::VerifiedEmail,
        Some(IdentityClaim::verified_email(email).unwrap()),
        IdentityBindingState::Confirmed,
        provenance,
        10,
    )
    .unwrap();
    let mut builder = collection.begin_delta();
    builder.add_entity(provider.into_entity()).unwrap();
    builder.add_entity(canonical.clone().into_entity()).unwrap();
    builder
        .add_assertion(GraphAssertion::IdentityBinding(employee_binding))
        .unwrap();
    builder
        .add_assertion(GraphAssertion::IdentityBinding(email_binding))
        .unwrap();
    (builder.build(), canonical)
}

fn claim_match_delta(
    source: &str,
    provider_id: &str,
    email: &str,
    canonical: &CanonicalIdentity,
) -> GraphDelta {
    let runtime = SourceRuntimeId::parse(format!("{source}-prod")).unwrap();
    let collection = CompleteCollection::new(
        canonical.entity().tenant_id().clone(),
        runtime.clone(),
        CollectionId::parse(format!("{source}-{provider_id}")).unwrap(),
        format!("{source}.users"),
        20,
    )
    .unwrap();
    let provider = ProviderIdentity::new(
        canonical.entity().tenant_id().clone(),
        runtime,
        ProviderKind::parse(format!("{source}.identity_user")).unwrap(),
        provider_id,
        format!("{source} account"),
    )
    .unwrap();
    let provenance = AssertionProvenance::direct(
        vec![
            ObservationRef::new(
                collection.receipt(),
                ObservationId::parse(format!("observation-{source}-{provider_id}")).unwrap(),
                format!("{source}.user:{provider_id}"),
            )
            .unwrap(),
        ],
        format!("{source}-identity-mapper"),
        "v1",
    )
    .unwrap();
    let binding = IdentityBindingAssertion::new(
        &provider,
        canonical,
        IdentityResolutionMethod::ExistingClaimMatch,
        Some(IdentityClaim::verified_email(email).unwrap()),
        IdentityBindingState::Confirmed,
        provenance,
        20,
    )
    .unwrap();
    let mut builder = collection.begin_delta();
    builder.add_entity(provider.into_entity()).unwrap();
    builder.add_entity(canonical.clone().into_entity()).unwrap();
    builder
        .add_assertion(GraphAssertion::IdentityBinding(binding))
        .unwrap();
    builder.build()
}
