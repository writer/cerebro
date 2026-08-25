//! PostgreSQL persistence for fenced source-page publication.

use cerebro_organizational_model::TenantId;
use cerebro_source_runtime_next::{PagePublication, PagePublicationState};
use serde_json::Value;
use tokio_postgres::{Row, Transaction};

use crate::{PostgresLedger, StoreError};

const PAGE_COLUMNS: &str = "tenant_id, logical_page_id, source_runtime_id, source_id, family_id, state, revision, publication_json";

impl PostgresLedger {
    /// Inserts a newly prepared page. Repeating the exact snapshot is
    /// idempotent; reusing its identity for different content fails closed.
    pub async fn prepare_page_publication(&self, page: &PagePublication) -> Result<(), StoreError> {
        if page.state() != PagePublicationState::Prepared || page.revision() != 1 {
            return Err(StoreError::Conflict(
                "only a newly prepared page can enter the publication ledger".to_owned(),
            ));
        }
        let revision = storage_revision(page.revision())?;
        let state = state_name(page.state());
        let snapshot = serde_json::to_value(page)?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, page.tenant_id().as_str()).await?;
        let stored = transaction
            .query_opt(
                r#"
INSERT INTO source_runtime_page_publications (
  tenant_id,
  logical_page_id,
  source_runtime_id,
  source_id,
  family_id,
  state,
  revision,
  publication_json
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, logical_page_id) DO UPDATE
SET updated_at = NOW()
WHERE source_runtime_page_publications.source_runtime_id = EXCLUDED.source_runtime_id
  AND source_runtime_page_publications.source_id = EXCLUDED.source_id
  AND source_runtime_page_publications.family_id = EXCLUDED.family_id
  AND source_runtime_page_publications.state = EXCLUDED.state
  AND source_runtime_page_publications.revision = EXCLUDED.revision
  AND source_runtime_page_publications.publication_json = EXCLUDED.publication_json
RETURNING revision
"#,
                &[
                    &page.tenant_id().as_str(),
                    &page.logical_page_id(),
                    &page.source_runtime_id().as_str(),
                    &page.source_id(),
                    &page.family_id(),
                    &state,
                    &revision,
                    &snapshot,
                ],
            )
            .await?;
        if stored.is_none() {
            return Err(StoreError::Conflict(
                "logical page identity already belongs to different publication content".to_owned(),
            ));
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Persists exactly one state-machine revision using compare-and-swap.
    /// An exact retry is idempotent; a stale or skipped revision fails closed.
    pub async fn persist_page_publication(
        &self,
        expected_revision: u64,
        page: &PagePublication,
    ) -> Result<(), StoreError> {
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("page publication revision overflow".to_owned()))?;
        if page.revision() != next_revision {
            return Err(StoreError::Conflict(
                "page publication persistence must advance exactly one revision".to_owned(),
            ));
        }
        let expected_revision = storage_revision(expected_revision)?;
        let revision = storage_revision(page.revision())?;
        let state = state_name(page.state());
        let snapshot = serde_json::to_value(page)?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, page.tenant_id().as_str()).await?;
        let changed = transaction
            .execute(
                r#"
UPDATE source_runtime_page_publications
SET state = $6,
    revision = $7,
    publication_json = $8,
    updated_at = NOW()
WHERE tenant_id = $1
  AND logical_page_id = $2
  AND source_runtime_id = $3
  AND source_id = $4
  AND family_id = $5
  AND revision = $9
"#,
                &[
                    &page.tenant_id().as_str(),
                    &page.logical_page_id(),
                    &page.source_runtime_id().as_str(),
                    &page.source_id(),
                    &page.family_id(),
                    &state,
                    &revision,
                    &snapshot,
                    &expected_revision,
                ],
            )
            .await?;
        if changed == 0 {
            let exact_retry = transaction
                .query_opt(
                    "SELECT 1 FROM source_runtime_page_publications WHERE tenant_id = $1 AND logical_page_id = $2 AND source_runtime_id = $3 AND source_id = $4 AND family_id = $5 AND state = $6 AND revision = $7 AND publication_json = $8",
                    &[
                        &page.tenant_id().as_str(),
                        &page.logical_page_id(),
                        &page.source_runtime_id().as_str(),
                        &page.source_id(),
                        &page.family_id(),
                        &state,
                        &revision,
                        &snapshot,
                    ],
                )
                .await?
                .is_some();
            if !exact_retry {
                return Err(StoreError::Conflict(
                    "page publication revision is stale or missing".to_owned(),
                ));
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Loads one page through tenant row-level security and revalidates its
    /// entire snapshot before returning it to recovery code.
    pub async fn load_page_publication(
        &self,
        tenant_id: &TenantId,
        logical_page_id: &str,
    ) -> Result<Option<PagePublication>, StoreError> {
        if logical_page_id.trim().is_empty() {
            return Err(StoreError::Conflict(
                "logical page id is required".to_owned(),
            ));
        }
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let query = format!(
            "SELECT {PAGE_COLUMNS} FROM source_runtime_page_publications WHERE tenant_id = $1 AND logical_page_id = $2"
        );
        let row = transaction
            .query_opt(&query, &[&tenant_id.as_str(), &logical_page_id])
            .await?;
        transaction.commit().await?;
        row.map(decode_page_publication).transpose()
    }

    /// Lists recoverable pages for one tenant in stable oldest-first order.
    /// Terminal and quarantined pages remain queryable by exact identity but
    /// are never admitted to automatic recovery.
    pub async fn recoverable_page_publications(
        &self,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<Vec<PagePublication>, StoreError> {
        if limit == 0 || limit > 500 {
            return Err(StoreError::Conflict(
                "page publication recovery limit is invalid".to_owned(),
            ));
        }
        let limit = i64::try_from(limit)
            .map_err(|_| StoreError::Conflict("page recovery limit overflow".to_owned()))?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let query = format!(
            "SELECT {PAGE_COLUMNS} FROM source_runtime_page_publications WHERE tenant_id = $1 AND state IN ('prepared', 'publishing', 'published', 'projected') ORDER BY updated_at, logical_page_id LIMIT $2"
        );
        let rows = transaction
            .query(&query, &[&tenant_id.as_str(), &limit])
            .await?;
        transaction.commit().await?;
        rows.into_iter().map(decode_page_publication).collect()
    }
}

fn decode_page_publication(row: Row) -> Result<PagePublication, StoreError> {
    let tenant_id: String = row.get(0);
    let logical_page_id: String = row.get(1);
    let source_runtime_id: String = row.get(2);
    let source_id: String = row.get(3);
    let family_id: String = row.get(4);
    let state: String = row.get(5);
    let revision: i64 = row.get(6);
    let snapshot: Value = row.get(7);
    let page = PagePublication::restore_snapshot(snapshot).map_err(|_| {
        StoreError::Conflict("stored page publication failed invariant validation".to_owned())
    })?;
    let revision = u64::try_from(revision)
        .map_err(|_| StoreError::Conflict("stored page revision is invalid".to_owned()))?;
    if page.tenant_id().as_str() != tenant_id
        || page.logical_page_id() != logical_page_id
        || page.source_runtime_id().as_str() != source_runtime_id
        || page.source_id() != source_id
        || page.family_id() != family_id
        || state_name(page.state()) != state
        || page.revision() != revision
    {
        return Err(StoreError::Conflict(
            "stored page publication metadata does not match its snapshot".to_owned(),
        ));
    }
    Ok(page)
}

fn state_name(state: PagePublicationState) -> &'static str {
    match state {
        PagePublicationState::Prepared => "prepared",
        PagePublicationState::Publishing => "publishing",
        PagePublicationState::Published => "published",
        PagePublicationState::Projected => "projected",
        PagePublicationState::Committed => "committed",
        PagePublicationState::Superseded => "superseded",
        PagePublicationState::Quarantined => "quarantined",
    }
}

fn storage_revision(revision: u64) -> Result<i64, StoreError> {
    if revision == 0 {
        return Err(StoreError::Conflict(
            "page publication revision must be positive".to_owned(),
        ));
    }
    i64::try_from(revision)
        .map_err(|_| StoreError::Conflict("page publication revision overflow".to_owned()))
}

async fn set_tenant(
    transaction: &Transaction<'_>,
    tenant_id: &str,
) -> Result<(), tokio_postgres::Error> {
    transaction
        .query_one(
            "SELECT set_config('cerebro.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_names_match_the_database_contract() {
        assert_eq!(state_name(PagePublicationState::Prepared), "prepared");
        assert_eq!(state_name(PagePublicationState::Publishing), "publishing");
        assert_eq!(state_name(PagePublicationState::Published), "published");
        assert_eq!(state_name(PagePublicationState::Projected), "projected");
        assert_eq!(state_name(PagePublicationState::Committed), "committed");
        assert_eq!(state_name(PagePublicationState::Superseded), "superseded");
        assert_eq!(state_name(PagePublicationState::Quarantined), "quarantined");
    }

    #[test]
    fn storage_revision_rejects_zero_and_overflow() {
        assert!(storage_revision(0).is_err());
        assert!(storage_revision(u64::MAX).is_err());
        assert_eq!(storage_revision(1).unwrap(), 1);
    }
}
