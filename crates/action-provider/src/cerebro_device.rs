use std::sync::Arc;

use async_trait::async_trait;
use cerebro_action_store::ActionDispatch;
use cerebro_platform_sdk::{ContentDigest, OpaqueId};
use postgres_native_tls::MakeTlsConnector;
use serde::Serialize;
use tokio::sync::Mutex;
use tokio_postgres::Client as PostgresClient;

use crate::{ProviderError, ProviderReceipt, ProviderStatus};

const PROVIDER: &str = "cerebro-device-auth";
const PROVIDER_ACTION: &str = "revoke";
const RECEIPT_SCHEMA: &str = "cerebro.device-action-receipt.v1";
const EXTERNAL_PREFIX: &str = "cerebro-device:revoke:";

#[derive(Clone)]
pub struct CerebroDeviceClient {
    store: Arc<dyn CerebroDeviceStore>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CerebroDeviceState {
    status: String,
    revoked_at_unix_ms: Option<u64>,
}

#[async_trait]
trait CerebroDeviceStore: Send + Sync {
    async fn revoke(&self, dispatch: &ActionDispatch) -> Result<CerebroDeviceState, ProviderError>;

    async fn observe(&self, dispatch: &ActionDispatch)
    -> Result<CerebroDeviceState, ProviderError>;
}

struct PostgresCerebroDeviceStore {
    client: Mutex<PostgresClient>,
}

impl CerebroDeviceClient {
    pub async fn connect_tls(connection_string: &str) -> Result<Self, ProviderError> {
        if connection_string.trim().is_empty() || connection_string.trim() != connection_string {
            return Err(ProviderError::InvalidConfiguration(
                "device PostgreSQL connection",
            ));
        }
        let tls = native_tls::TlsConnector::builder()
            .build()
            .map_err(|_| ProviderError::InvalidConfiguration("device PostgreSQL TLS"))?;
        let (client, connection) =
            tokio_postgres::connect(connection_string, MakeTlsConnector::new(tls))
                .await
                .map_err(|_| ProviderError::InvalidConfiguration("device PostgreSQL connection"))?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("Action device PostgreSQL connection closed: {error}");
            }
        });
        Ok(Self {
            store: Arc::new(PostgresCerebroDeviceStore {
                client: Mutex::new(client),
            }),
        })
    }

    #[cfg(test)]
    fn from_store(store: Arc<dyn CerebroDeviceStore>) -> Self {
        Self { store }
    }

    pub async fn dispatch(
        &self,
        dispatch: &ActionDispatch,
    ) -> Result<ProviderReceipt, ProviderError> {
        validate_dispatch(dispatch)?;
        let state = self.store.revoke(dispatch).await?;
        receipt(dispatch, state, None)
    }

    pub async fn observe(
        &self,
        dispatch: &ActionDispatch,
        expected_external_id: &OpaqueId,
    ) -> Result<ProviderReceipt, ProviderError> {
        validate_dispatch(dispatch)?;
        let expected = external_id(&dispatch.target_id)?;
        if expected_external_id != &expected {
            return Err(ProviderError::InvalidResponse("external id"));
        }
        let state = self.store.observe(dispatch).await?;
        receipt(dispatch, state, Some(expected_external_id))
    }
}

#[async_trait]
impl CerebroDeviceStore for PostgresCerebroDeviceStore {
    async fn revoke(&self, dispatch: &ActionDispatch) -> Result<CerebroDeviceState, ProviderError> {
        let requested_at = i64::try_from(dispatch.requested_at_unix_ms)
            .map_err(|_| ProviderError::InvalidDispatch("request time"))?;
        let reason = format!("Action {}", dispatch.operation_id);
        let row = self
            .client
            .lock()
            .await
            .query_opt(
                r#"
WITH updated AS (
  UPDATE device_records
  SET status = 'revoked',
      revoked_at = COALESCE(
        revoked_at,
        TO_TIMESTAMP($3::BIGINT::DOUBLE PRECISION / 1000.0)
      ),
      revoked_reason = CASE
        WHEN status = 'revoked' THEN revoked_reason
        ELSE $4
      END,
      updated_at = CASE
        WHEN status = 'revoked' THEN updated_at
        ELSE TO_TIMESTAMP($3::BIGINT::DOUBLE PRECISION / 1000.0)
      END
  WHERE device_id = $1 AND tenant_id = $2
  RETURNING status, revoked_at
)
SELECT
  status,
  (EXTRACT(EPOCH FROM revoked_at) * 1000)::BIGINT AS revoked_at_unix_ms
FROM updated
"#,
                &[
                    &dispatch.target_id,
                    &dispatch.tenant_id,
                    &requested_at,
                    &reason,
                ],
            )
            .await
            .map_err(|_| ProviderError::DispatchAmbiguous)?;
        row.map(state_from_row)
            .transpose()?
            .ok_or(ProviderError::DispatchRejected { status: 404 })
    }

    async fn observe(
        &self,
        dispatch: &ActionDispatch,
    ) -> Result<CerebroDeviceState, ProviderError> {
        let row = self
            .client
            .lock()
            .await
            .query_opt(
                r#"
SELECT
  status,
  (EXTRACT(EPOCH FROM revoked_at) * 1000)::BIGINT AS revoked_at_unix_ms
FROM device_records
WHERE device_id = $1 AND tenant_id = $2
"#,
                &[&dispatch.target_id, &dispatch.tenant_id],
            )
            .await
            .map_err(|_| ProviderError::ObservationUnavailable)?;
        row.map(state_from_row)
            .transpose()?
            .ok_or(ProviderError::ObservationUnavailable)
    }
}

fn state_from_row(row: tokio_postgres::Row) -> Result<CerebroDeviceState, ProviderError> {
    let revoked_at = row
        .try_get::<_, Option<i64>>("revoked_at_unix_ms")
        .map_err(|_| ProviderError::InvalidResponse("device timestamp"))?
        .map(|value| {
            u64::try_from(value).map_err(|_| ProviderError::InvalidResponse("device timestamp"))
        })
        .transpose()?;
    Ok(CerebroDeviceState {
        status: row
            .try_get("status")
            .map_err(|_| ProviderError::InvalidResponse("device status"))?,
        revoked_at_unix_ms: revoked_at,
    })
}

fn validate_dispatch(dispatch: &ActionDispatch) -> Result<(), ProviderError> {
    dispatch
        .validate()
        .map_err(|_| ProviderError::InvalidDispatch("content digest"))?;
    if dispatch.provider != PROVIDER {
        return Err(ProviderError::InvalidDispatch("provider"));
    }
    if dispatch.provider_action != PROVIDER_ACTION {
        return Err(ProviderError::InvalidDispatch("provider action"));
    }
    Ok(())
}

fn external_id(target_id: &str) -> Result<OpaqueId, ProviderError> {
    OpaqueId::parse(format!("{EXTERNAL_PREFIX}{target_id}"))
        .map_err(|_| ProviderError::InvalidDispatch("target"))
}

fn receipt(
    dispatch: &ActionDispatch,
    state: CerebroDeviceState,
    expected_external_id: Option<&OpaqueId>,
) -> Result<ProviderReceipt, ProviderError> {
    let external_id = external_id(&dispatch.target_id)?;
    if expected_external_id.is_some_and(|expected| expected != &external_id) {
        return Err(ProviderError::InvalidResponse("external id"));
    }
    let status = if state.status == "revoked" && state.revoked_at_unix_ms.is_some() {
        ProviderStatus::Succeeded
    } else {
        ProviderStatus::NeedsAttention
    };
    #[derive(Serialize)]
    struct DeviceReceipt<'a> {
        schema: &'static str,
        external_id: &'a str,
        action: &'a str,
        status: &'static str,
        target: &'a str,
        tenant_id: &'a str,
        finding_id: &'a str,
        idempotency_key: &'a str,
        device_status: &'a str,
        revoked_at_unix_ms: Option<u64>,
    }
    let bytes = serde_json::to_vec(&DeviceReceipt {
        schema: RECEIPT_SCHEMA,
        external_id: external_id.as_str(),
        action: &dispatch.provider_action,
        status: status.as_str(),
        target: &dispatch.target_id,
        tenant_id: &dispatch.tenant_id,
        finding_id: &dispatch.finding_id,
        idempotency_key: &dispatch.idempotency_key,
        device_status: &state.status,
        revoked_at_unix_ms: state.revoked_at_unix_ms,
    })
    .map_err(|_| ProviderError::InvalidResponse("device receipt"))?;
    Ok(ProviderReceipt {
        external_id,
        status,
        request_digest: Some(
            ContentDigest::parse(dispatch.dispatch_digest.clone())
                .map_err(|_| ProviderError::InvalidDispatch("dispatch digest"))?,
        ),
        response_digest: ContentDigest::of_bytes(bytes),
        updated_at_unix_s: state.revoked_at_unix_ms.map(|value| value / 1_000),
        completed_at_unix_s: if status.is_terminal() {
            state.revoked_at_unix_ms.map(|value| value / 1_000)
        } else {
            None
        },
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use cerebro_action_catalog::lookup;

    use super::*;

    struct MemoryDeviceStore {
        tenant_id: String,
        target_id: String,
        state: Mutex<CerebroDeviceState>,
        revocations: AtomicUsize,
    }

    #[async_trait]
    impl CerebroDeviceStore for MemoryDeviceStore {
        async fn revoke(
            &self,
            dispatch: &ActionDispatch,
        ) -> Result<CerebroDeviceState, ProviderError> {
            if dispatch.tenant_id != self.tenant_id || dispatch.target_id != self.target_id {
                return Err(ProviderError::DispatchRejected { status: 404 });
            }
            self.revocations.fetch_add(1, Ordering::SeqCst);
            let mut state = self.state.lock().await;
            if state.status != "revoked" {
                state.status = "revoked".to_owned();
                state.revoked_at_unix_ms = Some(dispatch.requested_at_unix_ms);
            }
            Ok(state.clone())
        }

        async fn observe(
            &self,
            dispatch: &ActionDispatch,
        ) -> Result<CerebroDeviceState, ProviderError> {
            if dispatch.tenant_id != self.tenant_id || dispatch.target_id != self.target_id {
                return Err(ProviderError::ObservationUnavailable);
            }
            Ok(self.state.lock().await.clone())
        }
    }

    #[tokio::test]
    async fn dispatch_is_tenant_scoped_idempotent_and_receipt_bound() {
        let store = Arc::new(MemoryDeviceStore {
            tenant_id: "tenant:one".to_owned(),
            target_id: "device:one".to_owned(),
            state: Mutex::new(CerebroDeviceState {
                status: "active".to_owned(),
                revoked_at_unix_ms: None,
            }),
            revocations: AtomicUsize::new(0),
        });
        let client = CerebroDeviceClient::from_store(store.clone());
        let dispatch = device_dispatch();

        let first = client.dispatch(&dispatch).await.expect("first dispatch");
        let second = client.dispatch(&dispatch).await.expect("idempotent replay");
        assert_eq!(first, second);
        assert_eq!(first.status, ProviderStatus::Succeeded);
        assert_eq!(
            first.external_id.as_str(),
            "cerebro-device:revoke:device:one"
        );
        assert_eq!(store.revocations.load(Ordering::SeqCst), 2);

        let observed = client
            .observe(&dispatch, &first.external_id)
            .await
            .expect("bound observation");
        assert_eq!(observed.response_digest, first.response_digest);
        assert_eq!(observed.status, ProviderStatus::Succeeded);
    }

    #[tokio::test]
    async fn dispatch_does_not_disclose_or_mutate_another_tenant() {
        let store = Arc::new(MemoryDeviceStore {
            tenant_id: "tenant:other".to_owned(),
            target_id: "device:one".to_owned(),
            state: Mutex::new(CerebroDeviceState {
                status: "active".to_owned(),
                revoked_at_unix_ms: None,
            }),
            revocations: AtomicUsize::new(0),
        });
        let client = CerebroDeviceClient::from_store(store.clone());

        assert_eq!(
            client.dispatch(&device_dispatch()).await,
            Err(ProviderError::DispatchRejected { status: 404 })
        );
        assert_eq!(store.revocations.load(Ordering::SeqCst), 0);
        assert_eq!(store.state.lock().await.status, "active");
    }

    #[tokio::test]
    async fn observation_rejects_a_receipt_from_another_target() {
        let store = Arc::new(MemoryDeviceStore {
            tenant_id: "tenant:one".to_owned(),
            target_id: "device:one".to_owned(),
            state: Mutex::new(CerebroDeviceState {
                status: "revoked".to_owned(),
                revoked_at_unix_ms: Some(42),
            }),
            revocations: AtomicUsize::new(0),
        });
        let client = CerebroDeviceClient::from_store(store);
        let wrong = OpaqueId::parse("cerebro-device:revoke:device:other").unwrap();

        assert_eq!(
            client.observe(&device_dispatch(), &wrong).await,
            Err(ProviderError::InvalidResponse("external id"))
        );
    }

    #[tokio::test]
    async fn dispatch_rejects_a_tampered_catalog_binding_before_mutation() {
        let store = Arc::new(MemoryDeviceStore {
            tenant_id: "tenant:one".to_owned(),
            target_id: "device:one".to_owned(),
            state: Mutex::new(CerebroDeviceState {
                status: "active".to_owned(),
                revoked_at_unix_ms: None,
            }),
            revocations: AtomicUsize::new(0),
        });
        let client = CerebroDeviceClient::from_store(store.clone());
        let mut dispatch = device_dispatch();
        dispatch.provider = "access-approvals".to_owned();

        assert!(matches!(
            client.dispatch(&dispatch).await,
            Err(ProviderError::InvalidDispatch(_))
        ));
        assert_eq!(store.revocations.load(Ordering::SeqCst), 0);
    }

    fn device_dispatch() -> ActionDispatch {
        let definition =
            lookup("endpoint.cerebro.revoke_device").expect("generated Action definition");
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
            target_id: "device:one".to_owned(),
            effect: definition.effect.to_owned(),
            idempotency_key: "idempotency:one".to_owned(),
            requested_by: "worker:one".to_owned(),
            requested_at_unix_ms: 42,
            dispatch_digest: ContentDigest::of_bytes("dispatch").to_string(),
        };
        dispatch.dispatch_digest = dispatch.computed_digest().unwrap().to_string();
        dispatch.validate().unwrap();
        dispatch
    }
}
