//! PostgreSQL persistence for fenced source-page publication.

use cerebro_organizational_model::TenantId;
use cerebro_source_runtime_next::{PagePublication, PagePublicationState};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_postgres::{Row, Transaction};

use crate::{PostgresLedger, StoreError};

const PAGE_COLUMNS: &str = "tenant_id, logical_page_id, source_runtime_id, source_id, family_id, state, revision, publication_json";
const MAX_EVENT_ENVELOPE_BYTES: usize = 16 << 20;
const MAX_PAGE_OUTBOX_BYTES: usize = 32 << 20;

/// One validated page and the exact secret-free envelope bytes required to
/// resume its ordered append publication without recollecting provider data.
pub struct PagePublicationOutbox {
    page: PagePublication,
    envelopes: Vec<Vec<u8>>,
}

impl PagePublicationOutbox {
    /// Returns the validated publication state and ordered event intents.
    pub fn page(&self) -> &PagePublication {
        &self.page
    }

    /// Returns canonical envelope bytes in the exact order of `page.events()`.
    pub fn envelopes(&self) -> &[Vec<u8>] {
        &self.envelopes
    }

    /// Consumes the outbox into its validated state and ordered envelopes.
    pub fn into_parts(self) -> (PagePublication, Vec<Vec<u8>>) {
        (self.page, self.envelopes)
    }
}

impl PostgresLedger {
    /// Inserts a newly prepared page. Repeating the exact snapshot is
    /// idempotent; reusing its identity for different content fails closed.
    pub async fn prepare_page_publication(
        &self,
        page: &PagePublication,
        envelopes: Vec<Vec<u8>>,
    ) -> Result<(), StoreError> {
        if page.state() != PagePublicationState::Prepared || page.revision() != 1 {
            return Err(StoreError::Conflict(
                "only a newly prepared page can enter the publication ledger".to_owned(),
            ));
        }
        let revision = storage_revision(page.revision())?;
        let state = state_name(page.state());
        let snapshot = serde_json::to_value(page)?;
        validate_envelopes(page, &envelopes)?;
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
        let ordinals = page
            .events()
            .iter()
            .map(|event| {
                i32::try_from(event.ordinal())
                    .map_err(|_| StoreError::Conflict("page event ordinal overflow".to_owned()))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let event_ids = page
            .events()
            .iter()
            .map(|event| event.event_id().as_str().to_owned())
            .collect::<Vec<_>>();
        let envelope_digests = page
            .events()
            .iter()
            .map(|event| event.envelope_sha256().to_owned())
            .collect::<Vec<_>>();
        let message_ids = page
            .events()
            .iter()
            .map(|event| event.message_id().to_owned())
            .collect::<Vec<_>>();
        let event_rows = transaction
            .query(
                r#"
INSERT INTO source_runtime_page_events (
  tenant_id,
  logical_page_id,
  ordinal,
  event_id,
  envelope_sha256,
  message_id,
  envelope
)
SELECT $1, $2, input.ordinal, input.event_id, input.envelope_sha256, input.message_id, input.envelope
FROM UNNEST($3::INTEGER[], $4::TEXT[], $5::TEXT[], $6::TEXT[], $7::BYTEA[])
  AS input(ordinal, event_id, envelope_sha256, message_id, envelope)
ON CONFLICT (tenant_id, logical_page_id, ordinal) DO UPDATE
SET ordinal = EXCLUDED.ordinal
WHERE source_runtime_page_events.event_id = EXCLUDED.event_id
  AND source_runtime_page_events.envelope_sha256 = EXCLUDED.envelope_sha256
  AND source_runtime_page_events.message_id = EXCLUDED.message_id
  AND source_runtime_page_events.envelope = EXCLUDED.envelope
RETURNING ordinal
"#,
                &[
                    &page.tenant_id().as_str(),
                    &page.logical_page_id(),
                    &ordinals,
                    &event_ids,
                    &envelope_digests,
                    &message_ids,
                    &envelopes,
                ],
            )
            .await?;
        if event_rows.len() != page.events().len() {
            return Err(StoreError::Conflict(
                "logical page outbox already contains different event bytes".to_owned(),
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

    /// Loads one page and the exact envelope outbox needed for publication.
    pub async fn load_page_publication_outbox(
        &self,
        tenant_id: &TenantId,
        logical_page_id: &str,
    ) -> Result<Option<PagePublicationOutbox>, StoreError> {
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
        let outbox = match row {
            Some(row) => {
                let page = decode_page_publication(row)?;
                Some(load_outbox(&transaction, page).await?)
            }
            None => None,
        };
        transaction.commit().await?;
        Ok(outbox)
    }

    /// Lists recoverable pages for one tenant in stable oldest-first order.
    /// Terminal and quarantined pages remain queryable by exact identity but
    /// are never admitted to automatic recovery.
    pub async fn recoverable_page_publications(
        &self,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<Vec<PagePublicationOutbox>, StoreError> {
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
        let mut outboxes = Vec::with_capacity(rows.len());
        for row in rows {
            let page = decode_page_publication(row)?;
            outboxes.push(load_outbox(&transaction, page).await?);
        }
        transaction.commit().await?;
        Ok(outboxes)
    }

    /// Lists pages that still require append-log publication in stable
    /// oldest-first order. Pages awaiting projection or progress commit are
    /// left to their owning recovery stages so they cannot starve publishers.
    pub async fn publishable_page_publications(
        &self,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<Vec<PagePublicationOutbox>, StoreError> {
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
            "SELECT {PAGE_COLUMNS} FROM source_runtime_page_publications WHERE tenant_id = $1 AND state IN ('prepared', 'publishing') ORDER BY updated_at, logical_page_id LIMIT $2"
        );
        let rows = transaction
            .query(&query, &[&tenant_id.as_str(), &limit])
            .await?;
        let mut outboxes = Vec::with_capacity(rows.len());
        for row in rows {
            let page = decode_page_publication(row)?;
            outboxes.push(load_outbox(&transaction, page).await?);
        }
        transaction.commit().await?;
        Ok(outboxes)
    }
}

async fn load_outbox(
    transaction: &Transaction<'_>,
    page: PagePublication,
) -> Result<PagePublicationOutbox, StoreError> {
    let rows = transaction
        .query(
            "SELECT ordinal, event_id, envelope_sha256, message_id, envelope FROM source_runtime_page_events WHERE tenant_id = $1 AND logical_page_id = $2 ORDER BY ordinal",
            &[&page.tenant_id().as_str(), &page.logical_page_id()],
        )
        .await?;
    if rows.len() != page.events().len() {
        return Err(StoreError::Conflict(
            "stored page publication outbox is incomplete".to_owned(),
        ));
    }
    let mut envelopes = Vec::with_capacity(rows.len());
    for (expected, row) in page.events().iter().zip(rows) {
        let ordinal: i32 = row.get(0);
        let event_id: String = row.get(1);
        let envelope_sha256: String = row.get(2);
        let message_id: String = row.get(3);
        let envelope: Vec<u8> = row.get(4);
        if i64::from(ordinal) != i64::from(expected.ordinal())
            || event_id != expected.event_id().as_str()
            || envelope_sha256 != expected.envelope_sha256()
            || message_id != expected.message_id()
        {
            return Err(StoreError::Conflict(
                "stored page event metadata does not match its intent".to_owned(),
            ));
        }
        envelopes.push(envelope);
    }
    validate_envelopes(&page, &envelopes)?;
    Ok(PagePublicationOutbox { page, envelopes })
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

fn validate_envelopes(page: &PagePublication, envelopes: &[Vec<u8>]) -> Result<(), StoreError> {
    if envelopes.len() != page.events().len() {
        return Err(StoreError::Conflict(
            "page publication outbox does not match its event count".to_owned(),
        ));
    }
    let mut total_bytes = 0_usize;
    for (event, envelope) in page.events().iter().zip(envelopes) {
        if envelope.is_empty() || envelope.len() > MAX_EVENT_ENVELOPE_BYTES {
            return Err(StoreError::Conflict(
                "page event envelope size is invalid".to_owned(),
            ));
        }
        total_bytes = total_bytes.checked_add(envelope.len()).ok_or_else(|| {
            StoreError::Conflict("page publication outbox size overflow".to_owned())
        })?;
        if total_bytes > MAX_PAGE_OUTBOX_BYTES {
            return Err(StoreError::Conflict(
                "page publication outbox exceeds its byte limit".to_owned(),
            ));
        }
        if digest_bytes(envelope) != event.envelope_sha256() {
            return Err(StoreError::Conflict(
                "page event envelope does not match its digest".to_owned(),
            ));
        }
    }
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
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

    #[test]
    fn envelope_digest_is_lowercase_sha256() {
        assert_eq!(
            digest_bytes(b"event"),
            "b8e1f80bd70ae0784c7855a451731b745fddb67749d23f637be9082b75e9575b"
        );
    }
}
