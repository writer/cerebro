use cerebro_action_catalog::lookup;
use cerebro_action_provider::{CerebroDeviceClient, ProviderError, ProviderStatus};
use cerebro_action_store::ActionDispatch;
use cerebro_platform_sdk::ContentDigest;
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn device_revocation_is_tenant_scoped_idempotent_and_observable() {
    let dsn = std::env::var("CEREBRO_TEST_POSTGRES_DSN")
        .expect("CEREBRO_TEST_POSTGRES_DSN is required for this ignored test");
    let (admin, connection) = tokio_postgres::connect(&dsn, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    admin
        .batch_execute(
            r#"
CREATE TABLE IF NOT EXISTS device_records (
  device_id TEXT PRIMARY KEY,
  hardware_uuid TEXT NOT NULL,
  serial_number TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT '',
  tenant_id TEXT NOT NULL,
  os_type TEXT NOT NULL DEFAULT '',
  os_version TEXT NOT NULL DEFAULT '',
  agent_version TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  enrolled_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revoked_reason TEXT NOT NULL DEFAULT '',
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#,
        )
        .await
        .unwrap();

    let target = format!("device:rust-provider:{}", std::process::id());
    admin
        .execute(
            "DELETE FROM device_records WHERE device_id = $1",
            &[&target],
        )
        .await
        .unwrap();
    admin
        .execute(
            "INSERT INTO device_records (device_id, hardware_uuid, tenant_id, enrolled_at, last_seen_at) VALUES ($1, $2, 'tenant:one', NOW(), NOW())",
            &[&target, &format!("hardware:{}", std::process::id())],
        )
        .await
        .unwrap();

    let provider = CerebroDeviceClient::connect_tls(&dsn).await.unwrap();
    let mut wrong_tenant = dispatch(&target);
    wrong_tenant.tenant_id = "tenant:other".to_owned();
    wrong_tenant.dispatch_digest = wrong_tenant.computed_digest().unwrap().to_string();
    assert_eq!(
        provider.dispatch(&wrong_tenant).await,
        Err(ProviderError::DispatchRejected { status: 404 })
    );
    assert_eq!(
        admin
            .query_one(
                "SELECT status FROM device_records WHERE device_id = $1",
                &[&target],
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "active"
    );

    let dispatch = dispatch(&target);
    let first = provider.dispatch(&dispatch).await.unwrap();
    let replay = provider.dispatch(&dispatch).await.unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.status, ProviderStatus::Succeeded);
    assert_eq!(
        provider
            .observe(&dispatch, &first.external_id)
            .await
            .unwrap()
            .response_digest,
        first.response_digest
    );
    let row = admin
        .query_one(
            "SELECT tenant_id, status, revoked_reason FROM device_records WHERE device_id = $1",
            &[&target],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "tenant:one");
    assert_eq!(row.get::<_, String>(1), "revoked");
    assert_eq!(row.get::<_, String>(2), "Action operation:one");

    admin
        .execute(
            "DELETE FROM device_records WHERE device_id = $1",
            &[&target],
        )
        .await
        .unwrap();
}

fn dispatch(target: &str) -> ActionDispatch {
    let definition = lookup("endpoint.cerebro.revoke_device").unwrap();
    let mut dispatch = ActionDispatch {
        tenant_id: "tenant:one".to_owned(),
        operation_id: "operation:one".to_owned(),
        operation_version: 6,
        proposal_digest: ContentDigest::of_bytes("proposal").to_string(),
        finding_id: "finding:one".to_owned(),
        finding_revision_digest: ContentDigest::of_bytes("finding revision").to_string(),
        finding_validation_receipt_digest: ContentDigest::of_bytes("finding validation")
            .to_string(),
        graph_revision: 1,
        action_kind: definition.id.to_owned(),
        action_definition_digest: definition.definition_digest.to_owned(),
        provider: definition.provider.to_owned(),
        provider_action: definition.provider_action.to_owned(),
        target_kind: definition.target_kind.to_owned(),
        target_id: target.to_owned(),
        effect: definition.effect.to_owned(),
        idempotency_key: "idempotency:one".to_owned(),
        requested_by: "worker:one".to_owned(),
        requested_at_unix_ms: 42_000,
        dispatch_digest: ContentDigest::of_bytes("dispatch").to_string(),
    };
    dispatch.dispatch_digest = dispatch.computed_digest().unwrap().to_string();
    dispatch
}
