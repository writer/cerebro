use std::{env, error::Error};

use cerebro_action_catalog::lookup;
use cerebro_action_store::{ActionStoreError, PostgresActionLedger};
use cerebro_platform_engine::ActionCommand;
use cerebro_platform_sdk::{
    ActionEffect, ActionOperationId, ActionProposal, ActionState, ActorId, ContentDigest,
    DecisionId, DecisionReceipt, FindingValidationDecision, FindingValidationReceipt,
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

    let validation = finding_validation("tenant:live:one");
    assert_eq!(
        ledger
            .record_finding_validation(validation.clone(), 5)
            .await?,
        validation
    );
    assert_eq!(
        ledger
            .record_finding_validation(validation.clone(), 6)
            .await?,
        validation
    );
    let initial_proposal = proposal("operation:live:one", "idempotency:live:one", &validation);
    let tenant = initial_proposal.tenant_id.clone();
    let operation_id = initial_proposal.operation_id.clone();
    let proposed = ledger.propose(initial_proposal.clone(), 10).await?;
    assert_eq!(proposed.state, ActionState::Proposed);
    assert_eq!(proposed.version, 1);
    assert_eq!(ledger.propose(initial_proposal, 11).await?, proposed);

    let mut conflicting = proposal("operation:live:two", "idempotency:live:one", &validation);
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

    let approved = ledger
        .transition(
            &tenant,
            &operation_id,
            &operator,
            waiting.version,
            ActionCommand::RecordApproval {
                receipt: DecisionReceipt {
                    decision_id: DecisionId::parse("decision:live:one")?,
                    proposal_digest: waiting.proposal.proposal_digest.to_string(),
                    approved: true,
                    decided_by: operator.clone(),
                    decided_at_unix_ms: 35,
                },
            },
            35,
        )
        .await?;
    let worker = ActorId::parse("worker:live:one")?;
    let claimed = ledger
        .transition(
            &tenant,
            &operation_id,
            &worker,
            approved.version,
            ActionCommand::Claim {
                worker_id: OpaqueId::parse(worker.as_str())?,
                claimed_at_unix_ms: 36,
                claim_expires_at_unix_ms: 100,
            },
            36,
        )
        .await?;
    let executing = ledger
        .transition(
            &tenant,
            &operation_id,
            &worker,
            claimed.version,
            ActionCommand::StartExecution {
                started_at_unix_ms: 40,
            },
            40,
        )
        .await?;
    let dispatch = ledger.get_dispatch(&tenant, &operation_id).await?;
    assert_eq!(dispatch.operation_version, executing.version);
    assert_eq!(
        dispatch.proposal_digest,
        executing.proposal.proposal_digest.to_string()
    );
    assert_eq!(
        dispatch.finding_id,
        executing.proposal.finding_id.to_string()
    );
    assert_eq!(
        dispatch.finding_validation_receipt_digest,
        validation.receipt_digest.to_string()
    );
    assert_eq!(
        dispatch.graph_revision,
        executing.proposal.graph_revision.get()
    );
    assert_eq!(dispatch.provider, "cerebro-device-auth");
    assert_eq!(dispatch.provider_action, "revoke");
    assert_eq!(dispatch.requested_by, worker.to_string());
    assert_eq!(
        ledger.list_open_dispatches(&tenant, 10).await?.dispatches,
        vec![dispatch.clone()]
    );
    assert!(matches!(
        ledger.get_dispatch(&other_tenant, &operation_id).await,
        Err(ActionStoreError::NotFound(_))
    ));
    let dispatched = ledger
        .transition(
            &tenant,
            &operation_id,
            &worker,
            executing.version,
            ActionCommand::RecordProviderReceipt {
                external_receipt_ref: OpaqueId::parse("receipt:live:one")?,
                provider_receipt_digest: ContentDigest::of_bytes("provider queued"),
                provider_status: "queued".to_owned(),
                executor_actor_id: worker.clone(),
                observed_at_unix_ms: 43,
            },
            43,
        )
        .await?;
    assert_eq!(dispatched.state, ActionState::Dispatched);
    assert_eq!(dispatched.provider_status.as_deref(), Some("queued"));
    assert_eq!(
        ledger.list_open_dispatches(&tenant, 10).await?.dispatches,
        vec![dispatch.clone()],
        "provider acceptance must keep the immutable dispatch open"
    );
    let running = ledger
        .transition(
            &tenant,
            &operation_id,
            &worker,
            dispatched.version,
            ActionCommand::ObserveProviderReceipt {
                provider_receipt_digest: ContentDigest::of_bytes("provider running"),
                provider_status: "running".to_owned(),
                observed_at_unix_ms: 44,
            },
            44,
        )
        .await?;
    assert_eq!(running.state, ActionState::Dispatched);
    assert_eq!(running.provider_status.as_deref(), Some("running"));
    assert!(matches!(
        ledger
            .transition(
                &tenant,
                &operation_id,
                &worker,
                running.version,
                ActionCommand::ObserveProviderReceipt {
                    provider_receipt_digest: ContentDigest::of_bytes("provider replay"),
                    provider_status: "running".to_owned(),
                    observed_at_unix_ms: 44,
                },
                45,
            )
            .await,
        Err(ActionStoreError::Conflict(_))
    ));

    let second = proposal(
        "operation:live:second",
        "idempotency:live:second",
        &validation,
    );
    ledger.propose(second.clone(), 41).await?;
    let other_validation = finding_validation(other_tenant.as_str());
    ledger
        .record_finding_validation(other_validation.clone(), 6)
        .await?;
    let other_tenant_proposal = proposal(
        "operation:live:other",
        "idempotency:live:other",
        &other_validation,
    );
    ledger.propose(other_tenant_proposal.clone(), 42).await?;

    let first_page = ledger.list(&tenant, 1, None).await?;
    assert_eq!(
        first_page.actions,
        vec![ledger.get(&tenant, &second.operation_id).await?]
    );
    let second_page = ledger
        .list(&tenant, 1, first_page.next_page_token.as_deref())
        .await?;
    assert_eq!(second_page.actions, vec![running]);
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
    let receipt_mutation = mutation_client.transaction().await?;
    receipt_mutation
        .query_one(
            "SELECT set_config('cerebro.tenant_id', $1, true)",
            &[&tenant.as_str()],
        )
        .await?;
    let error = receipt_mutation
        .execute(
            "UPDATE finding_validation_receipts SET expires_at_unix_ms = 900 WHERE tenant_id = $1 AND receipt_digest = $2",
            &[&tenant.as_str(), &validation.receipt_digest.as_str()],
        )
        .await
        .expect_err("finding validation receipt mutation must fail");
    assert!(
        error
            .as_db_error()
            .is_some_and(|error| error.message().contains("append-only"))
    );
    receipt_mutation.rollback().await?;

    let event_mutation = mutation_client.transaction().await?;
    event_mutation
        .query_one(
            "SELECT set_config('cerebro.tenant_id', $1, true)",
            &[&tenant.as_str()],
        )
        .await?;
    let error = event_mutation
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
    event_mutation.rollback().await?;

    let dispatch_mutation = mutation_client.transaction().await?;
    dispatch_mutation
        .query_one(
            "SELECT set_config('cerebro.tenant_id', $1, true)",
            &[&tenant.as_str()],
        )
        .await?;
    let error = dispatch_mutation
        .execute(
            "UPDATE action_dispatches SET provider_action = 'erase' WHERE tenant_id = $1 AND operation_id = $2",
            &[&tenant.as_str(), &operation_id.as_str()],
        )
        .await
        .expect_err("dispatch mutation must fail");
    assert!(
        error
            .as_db_error()
            .is_some_and(|error| error.message().contains("append-only"))
    );
    dispatch_mutation.rollback().await?;
    Ok(())
}

fn finding_validation(tenant_id: &str) -> FindingValidationReceipt {
    let policy = cerebro_policy_catalog::definitions()
        .first()
        .expect("generated policy");
    let mut receipt = FindingValidationReceipt {
        tenant_id: TenantId::parse(tenant_id).expect("valid tenant"),
        finding_id: OpaqueId::parse("finding:live:one").expect("valid finding"),
        finding_revision_digest: ContentDigest::of_bytes("finding-revision"),
        graph_revision: GraphRevision::new(1).expect("valid graph revision"),
        policy_id: policy.id.to_owned(),
        policy_definition_digest: ContentDigest::parse(policy.definition_digest)
            .expect("policy digest"),
        decision: FindingValidationDecision::Confirmed,
        evidence_digests: vec![ContentDigest::of_bytes("finding-evidence")],
        validated_by: ActorId::parse("validator:live:one").expect("valid validator"),
        validated_at_unix_ms: 5,
        expires_at_unix_ms: 1_000,
        receipt_digest: ContentDigest::of_bytes("placeholder"),
    };
    receipt
        .bind_computed_digest()
        .expect("bind finding validation digest");
    receipt
}

fn proposal(
    operation_id: &str,
    idempotency_key: &str,
    validation: &FindingValidationReceipt,
) -> ActionProposal {
    let definition = lookup("endpoint.cerebro.revoke_device").expect("generated Action definition");
    let mut proposal = ActionProposal {
        operation_id: ActionOperationId::parse(operation_id).expect("valid operation"),
        tenant_id: validation.tenant_id.clone(),
        finding_id: validation.finding_id.clone(),
        finding_revision_digest: validation.finding_revision_digest.clone(),
        finding_validation_receipt_digest: validation.receipt_digest.clone(),
        graph_revision: validation.graph_revision,
        action_kind: definition.id.to_owned(),
        action_definition_digest: ContentDigest::parse(definition.definition_digest)
            .expect("generated definition digest"),
        target_id: OpaqueId::parse("grant:live:one").expect("valid target"),
        expected_effects: vec![ActionEffect {
            target_id: OpaqueId::parse("grant:live:one").expect("valid target"),
            effect_kind: definition.effect.to_owned(),
            expected_state_digest: ContentDigest::of_bytes("expected"),
        }],
        rollback_ref: OpaqueId::parse("rollback:live:one").expect("valid rollback"),
        idempotency_key: OpaqueId::parse(idempotency_key).expect("valid idempotency key"),
        simulation_digest: ContentDigest::of_bytes("simulation"),
        verification_plan_digest: ContentDigest::of_bytes("verification-plan"),
        proposed_by: ActorId::parse("proposer:live:one").expect("valid actor"),
        proposed_at_unix_ms: 10,
        proposal_expires_at_unix_ms: 1_000,
        proposal_digest: ContentDigest::of_bytes("placeholder"),
    };
    proposal
        .bind_computed_digest()
        .expect("bind proposal digest");
    proposal
}
