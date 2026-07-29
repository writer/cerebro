use std::{collections::BTreeMap, env, error::Error};

use cerebro_organizational_model::{
    CollectionId, CompleteCollection, Entity, EntityId, EntityKind, ObservationId, SourceRuntimeId,
    TenantId,
};
use cerebro_organizational_store::{PostgresLedger, StoreError};
use cerebro_source_runtime_next::{CollectedBatch, CollectedScope, SourceRecord};
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL"]
async fn source_runtime_lease_generation_fences_stale_and_cross_tenant_commits()
-> Result<(), Box<dyn Error>> {
    let dsn = env::var("CEREBRO_TEST_POSTGRES_DSN")?;
    let (admin, admin_connection) = tokio_postgres::connect(&dsn, NoTls).await?;
    tokio::spawn(async move {
        admin_connection.await.expect("PostgreSQL admin connection");
    });
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls).await?;
    tokio::spawn(async move {
        connection.await.expect("PostgreSQL ledger connection");
    });
    let ledger = PostgresLedger::from_client(client);
    ledger.migrate().await?;

    let suffix = std::process::id();
    let tenant = TenantId::parse(format!("tenant-rust-lease-{suffix}"))?;
    let other_tenant = TenantId::parse(format!("tenant-rust-lease-other-{suffix}"))?;
    let runtime = SourceRuntimeId::parse(format!("runtime-rust-lease-{suffix}"))?;
    admin
        .execute(
            "INSERT INTO source_runtimes (id, runtime_json) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET runtime_json = EXCLUDED.runtime_json, lease_owner = NULL, lease_expires_at = NULL, lease_generation = 0",
            &[
                &runtime.as_str(),
                &serde_json::json!({
                    "id": runtime.as_str(),
                    "tenant_id": tenant.as_str(),
                    "source_id": "fixture",
                    "config": {
                        "family": "resources",
                        "base_url": "https://provider.example.test",
                        "token": "env:CEREBRO_SOURCE_FIXTURE_TOKEN"
                    },
                    "checkpoint": {
                        "watermark": "2026-07-28T00:00:00Z",
                        "cursor_opaque": "{\"token\":\"page:1\",\"resumable_checkpoint\":true}"
                    },
                    "next_cursor": {"opaque": "page:2"}
                }),
            ],
        )
        .await?;

    let stored = ledger.load_source_runtime(&runtime).await?;
    assert_eq!(stored.runtime_id(), &runtime);
    assert_eq!(stored.tenant_id(), &tenant);
    assert_eq!(stored.source_id(), "fixture");
    assert_eq!(stored.cursor(), Some("page:2"));
    assert_eq!(
        stored.config().get("token").map(String::as_str),
        Some("env:CEREBRO_SOURCE_FIXTURE_TOKEN")
    );

    let vault_runtime = SourceRuntimeId::parse("runtime-rust-vault-vector")?;
    let vault_tenant = TenantId::parse("tenant-rust-vault-vector")?;
    admin
        .execute(
            "INSERT INTO source_runtimes (id, runtime_json)
             VALUES ($1, $2)
             ON CONFLICT (id) DO UPDATE
             SET runtime_json = EXCLUDED.runtime_json,
                 lease_owner = NULL,
                 lease_expires_at = NULL",
            &[
                &vault_runtime.as_str(),
                &serde_json::json!({
                    "id": vault_runtime.as_str(),
                    "tenant_id": vault_tenant.as_str(),
                    "source_id": "fixture",
                    "config": {
                        "family": "resources",
                        "base_url": "https://provider.example.test",
                        "token": "credential:cred_rust_vault_vector:token"
                    }
                }),
            ],
        )
        .await?;
    let sealed = br#"{"algorithm":"AES-256-GCM","nonce":"AQEBAQEBAQEBAQEB","ciphertext":"WVIkjmqCn2b0Tnckdm9i17GWVkHlpoJhplPvYIkQXqDrIeD5w1o39L5GQmuOCeB5OTZpfeTLQxaxMJEk1c8gCPYa38JQ9p8H4eQx"}"#;
    admin
        .execute(
            "INSERT INTO connector_credentials (
               id, tenant_id, source_id, runtime_id, credential_store_id,
               status, key_id, fields_json, sealed
             )
             VALUES ($1, $2, $3, $4, 'cerebro_vault', 'valid', $5, $6, $7)
             ON CONFLICT (id) DO UPDATE
             SET tenant_id = EXCLUDED.tenant_id,
                 source_id = EXCLUDED.source_id,
                 runtime_id = EXCLUDED.runtime_id,
                 credential_store_id = EXCLUDED.credential_store_id,
                 status = EXCLUDED.status,
                 key_id = EXCLUDED.key_id,
                 fields_json = EXCLUDED.fields_json,
                 sealed = EXCLUDED.sealed,
                 last_used_at = NULL",
            &[
                &"cred_rust_vault_vector",
                &vault_tenant.as_str(),
                &"fixture",
                &vault_runtime.as_str(),
                &"connector-vault-14035dbb6492f0ed",
                &serde_json::json!(["other", "token"]),
                &sealed.as_slice(),
            ],
        )
        .await?;
    admin
        .execute(
            "DELETE FROM connector_credential_audit_events WHERE credential_id = $1",
            &[&"cred_rust_vault_vector"],
        )
        .await?;
    let vault_stored = ledger.load_source_runtime(&vault_runtime).await?;
    let resolved = ledger
        .resolve_connector_credential_references(
            &vault_stored,
            vault_stored.config(),
            "test-vault-key",
        )
        .await?;
    assert_eq!(
        resolved.get("token").map(String::as_str),
        Some("secret-token")
    );
    ledger
        .resolve_connector_credential_references(
            &vault_stored,
            vault_stored.config(),
            "test-vault-key",
        )
        .await?;
    let audit_count: i64 = admin
        .query_one(
            "SELECT COUNT(*) FROM connector_credential_audit_events
             WHERE credential_id = $1 AND event_type = 'used'",
            &[&"cred_rust_vault_vector"],
        )
        .await?
        .get(0);
    assert_eq!(audit_count, 1);
    admin
        .execute(
            "UPDATE connector_credentials SET status = 'revoked' WHERE id = $1",
            &[&"cred_rust_vault_vector"],
        )
        .await?;
    assert!(
        ledger
            .resolve_connector_credential_references(
                &vault_stored,
                vault_stored.config(),
                "test-vault-key",
            )
            .await
            .is_err()
    );

    assert!(
        ledger
            .acquire_source_runtime_lease(&other_tenant, &runtime, "worker:wrong-tenant", 60_000)
            .await?
            .is_none()
    );
    let first = ledger
        .acquire_source_runtime_lease(&tenant, &runtime, "worker:one", 60_000)
        .await?
        .expect("first lease");
    let replay = ledger
        .acquire_source_runtime_lease(&tenant, &runtime, "worker:one", 60_000)
        .await?
        .expect("same owner reacquires its lease");
    assert_eq!(replay.generation(), first.generation());
    assert!(
        ledger
            .acquire_source_runtime_lease(&tenant, &runtime, "worker:two", 60_000)
            .await?
            .is_none()
    );
    assert!(ledger.renew_source_runtime_lease(&first, 60_000).await?);

    admin
        .execute(
            "UPDATE source_runtimes SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
            &[&runtime.as_str()],
        )
        .await?;
    assert!(!ledger.renew_source_runtime_lease(&first, 60_000).await?);
    let successor = ledger
        .acquire_source_runtime_lease(&tenant, &runtime, "worker:two", 60_000)
        .await?
        .expect("successor lease");
    assert!(successor.generation() > first.generation());

    let collection = CompleteCollection::new(
        tenant.clone(),
        runtime.clone(),
        CollectionId::parse(format!("collection-rust-lease-{suffix}"))?,
        "fixture.resources",
        10,
    )?;
    let observation_id = ObservationId::parse(format!("observation-rust-lease-{suffix}"))?;
    let entity = Entity::canonical(
        tenant.clone(),
        EntityId::parse(format!("resource-rust-lease-{suffix}"))?,
        EntityKind::Resource,
        "Fenced resource",
    )?;
    let mut builder = collection.clone().begin_delta();
    builder.add_entity(entity)?;
    let delta = builder.build();
    let batch = CollectedBatch {
        scope: CollectedScope::Complete(collection),
        records: vec![SourceRecord {
            observation_id,
            family: "resources".to_owned(),
            provider_kind: "fixture.resource".to_owned(),
            provider_id: format!("provider-resource-{suffix}"),
            fields: BTreeMap::new(),
            payload: serde_json::json!({"id": format!("provider-resource-{suffix}")}),
        }],
        next_cursor: None,
    };

    assert!(matches!(
        ledger.commit_pending_fenced(&batch, &delta, &first).await,
        Err(StoreError::Conflict(message))
            if message == "source runtime lease was lost before commit"
    ));
    let stale_progress: serde_json::Value = admin
        .query_one(
            "SELECT runtime_json FROM source_runtimes WHERE id = $1",
            &[&runtime.as_str()],
        )
        .await?
        .get(0);
    assert_eq!(
        stale_progress
            .pointer("/next_cursor/opaque")
            .and_then(serde_json::Value::as_str),
        Some("page:2")
    );
    assert!(stale_progress.get("last_synced_at").is_none());

    let receipt = ledger
        .commit_pending_fenced(&batch, &delta, &successor)
        .await?;
    assert_eq!(receipt.tenant_id, tenant);
    let committed_progress: serde_json::Value = admin
        .query_one(
            "SELECT runtime_json FROM source_runtimes WHERE id = $1",
            &[&runtime.as_str()],
        )
        .await?
        .get(0);
    assert!(committed_progress.get("next_cursor").is_none());
    assert_eq!(
        committed_progress
            .pointer("/checkpoint/cursor_opaque")
            .and_then(serde_json::Value::as_str),
        Some("")
    );
    assert_eq!(
        committed_progress
            .pointer("/checkpoint/watermark")
            .and_then(serde_json::Value::as_str),
        Some("2026-07-28T00:00:00Z")
    );
    assert!(
        committed_progress
            .get("last_synced_at")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|timestamp| timestamp.contains('T'))
    );

    assert!(!ledger.release_source_runtime_lease(&first).await?);
    assert!(ledger.release_source_runtime_lease(&successor).await?);
    assert!(matches!(
        ledger
            .commit_pending_fenced(&batch, &delta, &successor)
            .await,
        Err(StoreError::Conflict(message))
            if message == "source runtime lease was lost before commit"
    ));
    let after_rejected_replay: serde_json::Value = admin
        .query_one(
            "SELECT runtime_json FROM source_runtimes WHERE id = $1",
            &[&runtime.as_str()],
        )
        .await?
        .get(0);
    assert_eq!(after_rejected_replay, committed_progress);
    Ok(())
}
