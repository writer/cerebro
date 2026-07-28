use std::{env, error::Error};

use cerebro_action_store::{ActionStoreError, PostgresActionLedger};
use cerebro_platform_engine::ActionCommand;
use cerebro_platform_sdk::{
    ActionEffect, ActionOperationId, ActionProposal, ActionState, ActorId, ContentDigest,
    GraphRevision, OpaqueId, TenantId,
};
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn durable_actions_are_tenant_scoped_idempotent_versioned_and_append_only()
-> Result<(), Box<dyn Error>> {
    let dsn = env::var("CEREBRO_TEST_POSTGRES_DSN")?;
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls).await?;
    tokio::spawn(async move {
        connection.await.expect("PostgreSQL test connection");
    });
    let ledger = PostgresActionLedger::from_client(client);
    ledger.migrate().await?;

    let initial_proposal = proposal("operation:live:one", "idempotency:live:one");
    let tenant = initial_proposal.tenant_id.clone();
    let operation_id = initial_proposal.operation_id.clone();
    let proposed = ledger.propose(initial_proposal.clone(), 10).await?;
    assert_eq!(proposed.state, ActionState::Proposed);
    assert_eq!(proposed.version, 1);
    assert_eq!(ledger.propose(initial_proposal, 11).await?, proposed);

    let mut conflicting = proposal("operation:live:two", "idempotency:live:one");
    conflicting
        .bind_computed_digest()
        .expect("bind conflicting proposal");
    assert!(matches!(
        ledger.propose(conflicting, 12).await,
        Err(ActionStoreError::Conflict(_))
    ));

    let other_tenant = TenantId::parse("tenant:live:other")?;
    let operator = ActorId::parse("operator:live:one")?;
    assert!(matches!(
        ledger.get(&other_tenant, &operation_id).await,
        Err(ActionStoreError::NotFound(_))
    ));

    let simulated = ledger
        .transition(
            &tenant,
            &operation_id,
            &operator,
            1,
            ActionCommand::RecordSimulation,
            20,
        )
        .await?;
    let waiting = ledger
        .transition(
            &tenant,
            &operation_id,
            &operator,
            2,
            ActionCommand::RequestApproval,
            30,
        )
        .await?;
    assert_eq!(waiting.state, ActionState::WaitingForApproval);
    assert!(matches!(
        ledger
            .transition(
                &tenant,
                &operation_id,
                &operator,
                1,
                ActionCommand::RecordSimulation,
                31,
            )
            .await,
        Err(ActionStoreError::Conflict(_))
    ));
    assert!(matches!(
        ledger
            .transition(
                &tenant,
                &operation_id,
                &operator,
                waiting.version,
                ActionCommand::Fail,
                19,
            )
            .await,
        Err(ActionStoreError::Conflict(_))
    ));
    assert_eq!(ledger.get(&tenant, &operation_id).await?, waiting);

    let history = ledger.history(&tenant, &operation_id).await?;
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].event_kind, "proposed");
    assert_eq!(history[0].actor_id, proposed.proposal.proposed_by);
    assert_eq!(history[1].actor_id, operator);
    assert_eq!(history[1].event_kind, "record_simulation");
    assert_eq!(history[2].event_kind, "request_approval");
    assert_eq!(history[1].operation, simulated);
    assert_eq!(history[2].operation, waiting);
    assert!(history[0].command_digest.is_none());
    assert!(history[1].command_digest.is_some());

    let second = proposal("operation:live:second", "idempotency:live:second");
    ledger.propose(second.clone(), 40).await?;
    let mut other_tenant_proposal = proposal("operation:live:other", "idempotency:live:other");
    other_tenant_proposal.tenant_id = other_tenant.clone();
    other_tenant_proposal
        .bind_computed_digest()
        .expect("bind other tenant proposal");
    ledger.propose(other_tenant_proposal.clone(), 41).await?;

    let first_page = ledger.list(&tenant, 1, None).await?;
    assert_eq!(
        first_page.actions,
        vec![ledger.get(&tenant, &second.operation_id).await?]
    );
    let second_page = ledger
        .list(&tenant, 1, first_page.next_page_token.as_deref())
        .await?;
    assert_eq!(second_page.actions, vec![waiting]);
    assert!(second_page.next_page_token.is_none());
    assert_eq!(
        ledger.list(&other_tenant, 10, None).await?.actions,
        vec![
            ledger
                .get(&other_tenant, &other_tenant_proposal.operation_id)
                .await?
        ]
    );
    assert!(matches!(
        ledger.list(&tenant, 10, Some("v1.invalid")).await,
        Err(ActionStoreError::InvalidPageToken)
    ));

    let (mut mutation_client, mutation_connection) = tokio_postgres::connect(&dsn, NoTls).await?;
    tokio::spawn(async move {
        mutation_connection
            .await
            .expect("PostgreSQL mutation test connection");
    });
    let mutation = mutation_client.transaction().await?;
    mutation
        .query_one(
            "SELECT set_config('cerebro.tenant_id', $1, true)",
            &[&tenant.as_str()],
        )
        .await?;
    let error = mutation
        .execute(
            "UPDATE action_operation_events SET committed_at_unix_ms = 40 WHERE tenant_id = $1 AND operation_id = $2 AND version = 2",
            &[&tenant.as_str(), &operation_id.as_str()],
        )
        .await
        .expect_err("event mutation must fail");
    assert!(
        error
            .as_db_error()
            .is_some_and(|error| error.message().contains("append-only"))
    );
    Ok(())
}

fn proposal(operation_id: &str, idempotency_key: &str) -> ActionProposal {
    let mut proposal = ActionProposal {
        operation_id: ActionOperationId::parse(operation_id).expect("valid operation"),
        tenant_id: TenantId::parse("tenant:live:one").expect("valid tenant"),
        finding_id: OpaqueId::parse("finding:live:one").expect("valid finding"),
        finding_revision_digest: ContentDigest::of_bytes("finding-revision"),
        finding_validation_receipt_digest: ContentDigest::of_bytes("finding-validation"),
        graph_revision: GraphRevision::new(1).expect("valid graph revision"),
        action_kind: "revoke_access".to_owned(),
        action_definition_digest: ContentDigest::of_bytes("action-definition"),
        target_id: OpaqueId::parse("grant:live:one").expect("valid target"),
        expected_effects: vec![ActionEffect {
            target_id: OpaqueId::parse("grant:live:one").expect("valid target"),
            effect_kind: "access_removed".to_owned(),
            expected_state_digest: ContentDigest::of_bytes("expected"),
        }],
        rollback_ref: OpaqueId::parse("rollback:live:one").expect("valid rollback"),
        idempotency_key: OpaqueId::parse(idempotency_key).expect("valid idempotency key"),
        simulation_digest: ContentDigest::of_bytes("simulation"),
        verification_plan_digest: ContentDigest::of_bytes("verification-plan"),
        proposed_by: ActorId::parse("proposer:live:one").expect("valid actor"),
        proposed_at_unix_ms: 1,
        proposal_expires_at_unix_ms: 1_000,
        proposal_digest: ContentDigest::of_bytes("placeholder"),
    };
    proposal
        .bind_computed_digest()
        .expect("bind proposal digest");
    proposal
}
