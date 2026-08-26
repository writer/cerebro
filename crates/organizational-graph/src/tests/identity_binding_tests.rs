use cerebro_organizational_model::IdentityClaimKind;

use super::*;

#[test]
fn one_provider_identity_cannot_bind_to_two_canonical_identities() {
    let mut graph = OrganizationalGraph::new();
    let first = identity_delta("00u1", "person-1", IdentityBindingState::Confirmed, None);
    let (provider_identity, existing_canonical_identity) = match &first.assertions()[0] {
        GraphAssertion::IdentityBinding(binding) => (
            binding.provider_identity().clone(),
            binding.canonical_identity().clone(),
        ),
        _ => panic!("identity delta must contain an identity binding"),
    };
    graph.apply(first).unwrap();

    let second = identity_delta("00u1", "person-2", IdentityBindingState::Confirmed, None);
    let requested_canonical_identity = match &second.assertions()[0] {
        GraphAssertion::IdentityBinding(binding) => binding.canonical_identity().clone(),
        _ => panic!("identity delta must contain an identity binding"),
    };
    let revision = graph.graph_revision(&TenantId::parse("tenant-a").unwrap());

    assert_eq!(
        graph.apply(second),
        Err(GraphError::IdentityAlreadyBound {
            provider_identity,
            existing_canonical_identity,
            requested_canonical_identity,
        })
    );
    let tenant = TenantId::parse("tenant-a").unwrap();
    assert_eq!(graph.graph_revision(&tenant), revision);
    assert_eq!(graph.assertions(&tenant).len(), 1);
    assert_eq!(graph.entities(&tenant).len(), 2);
}

#[test]
fn one_authoritative_claim_cannot_create_two_canonical_identities() {
    let mut graph = OrganizationalGraph::new();
    let first = identity_delta(
        "00u1",
        "person-1",
        IdentityBindingState::Confirmed,
        Some(IdentityClaim::employee_id("employee-1").unwrap()),
    );
    let claim_kind = IdentityClaimKind::EmployeeId;
    let claim_value = "employee-1".to_owned();
    let existing_canonical_identity = match &first.assertions()[0] {
        GraphAssertion::IdentityBinding(binding) => binding.canonical_identity().clone(),
        _ => panic!("identity delta must contain an identity binding"),
    };
    let second = identity_delta(
        "00u2",
        "person-2",
        IdentityBindingState::Confirmed,
        Some(IdentityClaim::employee_id("employee-1").unwrap()),
    );
    let requested_canonical_identity = match &second.assertions()[0] {
        GraphAssertion::IdentityBinding(binding) => binding.canonical_identity().clone(),
        _ => panic!("identity delta must contain an identity binding"),
    };
    graph.apply(first).unwrap();
    let revision = graph.graph_revision(&TenantId::parse("tenant-a").unwrap());
    assert_eq!(
        graph.apply(second),
        Err(GraphError::IdentityClaimAlreadyBound {
            claim_kind,
            claim_value,
            existing_canonical_identity,
            requested_canonical_identity,
        })
    );
    let tenant = TenantId::parse("tenant-a").unwrap();
    assert_eq!(graph.graph_revision(&tenant), revision);
    assert_eq!(graph.assertions(&tenant).len(), 1);
    assert_eq!(graph.entities(&tenant).len(), 2);
}

#[test]
fn verified_email_binding_requires_an_authoritative_anchor() {
    let mut graph = OrganizationalGraph::new();
    let delta = identity_delta_with_method(
        "00u-unanchored",
        "person-unanchored",
        IdentityResolutionMethod::VerifiedEmail,
        IdentityBindingState::Confirmed,
        Some(IdentityClaim::verified_email("person@example.com").unwrap()),
    );
    let canonical_identity = match &delta.assertions()[0] {
        GraphAssertion::IdentityBinding(binding) => binding.canonical_identity().clone(),
        _ => panic!("identity delta must contain an identity binding"),
    };

    assert_eq!(
        graph.apply(delta),
        Err(GraphError::CanonicalIdentityUnanchored(canonical_identity))
    );
    let tenant = TenantId::parse("tenant-a").unwrap();
    assert_eq!(graph.graph_revision(&tenant), 0);
    assert!(graph.entities(&tenant).is_empty());
    assert!(graph.assertions(&tenant).is_empty());
}

#[test]
fn existing_claim_match_requires_a_confirmed_claim() {
    let tenant = TenantId::parse("tenant-a").unwrap();
    let canonical = CanonicalIdentity::new(
        tenant,
        CanonicalIdentityId::parse("person-without-claim").unwrap(),
        "Canonical Person",
    )
    .unwrap();
    let delta = claim_match_delta(
        "github",
        "github-without-claim",
        "missing@example.com",
        &canonical,
    );
    let requested_canonical_identity = match &delta.assertions()[0] {
        GraphAssertion::IdentityBinding(binding) => binding.canonical_identity().clone(),
        _ => panic!("claim-match delta must contain an identity binding"),
    };
    let mut graph = OrganizationalGraph::new();

    assert_eq!(
        graph.apply(delta),
        Err(GraphError::IdentityClaimNotFound {
            claim_kind: IdentityClaimKind::VerifiedEmail,
            claim_value: "missing@example.com".to_owned(),
            requested_canonical_identity,
        })
    );
    assert_eq!(
        graph.graph_revision(&TenantId::parse("tenant-a").unwrap()),
        0
    );
}

#[test]
fn workforce_claims_unify_okta_github_and_slack_accounts() {
    let mut graph = OrganizationalGraph::new();
    let (workforce, canonical) = workforce_delta("employee-1", "person@example.com");
    graph.apply(workforce).unwrap();
    graph
        .apply(claim_match_delta(
            "github",
            "github-1",
            "person@example.com",
            &canonical,
        ))
        .unwrap();
    graph
        .apply(claim_match_delta(
            "slack",
            "slack-1",
            "person@example.com",
            &canonical,
        ))
        .unwrap();
    let tenant = TenantId::parse("tenant-a").unwrap();
    assert_eq!(
        graph
            .entities(&tenant)
            .iter()
            .filter(|entity| entity.kind() == &cerebro_organizational_model::EntityKind::Person)
            .count(),
        1
    );
}

#[test]
fn shared_alias_cannot_create_or_redirect_a_person() {
    let mut graph = OrganizationalGraph::new();
    let (workforce, canonical) = workforce_delta("employee-1", "person@example.com");
    graph.apply(workforce).unwrap();
    assert!(matches!(
        graph.apply(claim_match_delta(
            "slack",
            "slack-2",
            "shared@example.com",
            &canonical,
        )),
        Err(GraphError::IdentityClaimNotFound { .. })
    ));
}

#[test]
fn non_directory_provider_cannot_seed_verified_email() {
    let tenant = TenantId::parse("tenant-a").unwrap();
    let runtime = SourceRuntimeId::parse("slack-prod").unwrap();
    let collection = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse("slack-user-1").unwrap(),
        "slack.users",
        10,
    )
    .unwrap();
    let provider = ProviderIdentity::new(
        tenant.clone(),
        runtime,
        ProviderKind::parse("slack.identity_user").unwrap(),
        "U1",
        "Slack account",
    )
    .unwrap();
    let employee_claim = IdentityClaim::employee_id("employee-1").unwrap();
    let canonical =
        CanonicalIdentity::for_claim(tenant, &employee_claim, "Canonical Person").unwrap();
    let provenance = AssertionProvenance::direct(
        vec![
            ObservationRef::new(
                collection.receipt(),
                ObservationId::parse("observation-slack-1").unwrap(),
                "slack.user:U1",
            )
            .unwrap(),
        ],
        "slack-identity-mapper",
        "v1",
    )
    .unwrap();
    assert_eq!(
        IdentityBindingAssertion::new(
            &provider,
            &canonical,
            IdentityResolutionMethod::VerifiedEmail,
            Some(IdentityClaim::verified_email("person@example.com").unwrap()),
            IdentityBindingState::Confirmed,
            provenance,
            10,
        ),
        Err(cerebro_organizational_model::ModelError::InvalidIdentityBinding)
    );
}
