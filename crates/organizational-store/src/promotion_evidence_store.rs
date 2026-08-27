//! Read-only verification of promotion evidence against durable PostgreSQL records.

use std::collections::BTreeSet;

use cerebro_source_catalog::{PagePublicationReceiptReference, PersistedReceiptReference};
use cerebro_source_runtime_next::{PagePublication, PagePublicationState};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{PostgresLedger, ProjectionPromotionRequest, StoreError};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedPromotionReceiptKind {
    DurableCollection,
    AuthenticatedCollection,
    AppendProjectionCheckpoint,
    LeaseRestart,
    Parity,
    RuntimeRevision,
    ProductRead,
    PromotionApproval,
    Recovery,
}

/// The kind of durably persisted receipt backing a promotion qualification's
/// product-read, promotion-approval, or rollback proof. Distinct from
/// [`VerifiedPromotionReceiptKind`], which additionally covers receipt kinds
/// verified against other tables (collections, page publications, parity).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionEvidenceReceiptKind {
    ProductRead,
    PromotionApproval,
    Rollback,
}

impl PromotionEvidenceReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProductRead => "product_read",
            Self::PromotionApproval => "promotion_approval",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedPromotionReceipt {
    kind: VerifiedPromotionReceiptKind,
    receipt_id: String,
    receipt_digest: String,
}

impl VerifiedPromotionReceipt {
    fn new(
        kind: VerifiedPromotionReceiptKind,
        receipt_id: impl Into<String>,
        receipt_digest: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            receipt_id: receipt_id.into(),
            receipt_digest: receipt_digest.into(),
        }
    }

    pub fn kind(&self) -> VerifiedPromotionReceiptKind {
        self.kind
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct PromotionEvidenceVerification {
    tenant_id: String,
    source_id: String,
    family_id: String,
    source_runtime_id: String,
    runtime_revision_sha256: String,
    reasons: Vec<String>,
    receipts: Vec<VerifiedPromotionReceipt>,
}

impl PromotionEvidenceVerification {
    fn verified_by_store(
        tenant_id: impl Into<String>,
        source_id: impl Into<String>,
        family_id: impl Into<String>,
        source_runtime_id: impl Into<String>,
        runtime_revision_sha256: impl Into<String>,
        mut reasons: Vec<String>,
        mut receipts: Vec<VerifiedPromotionReceipt>,
    ) -> Self {
        reasons.sort();
        reasons.dedup();
        receipts.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.receipt_id.cmp(&right.receipt_id))
                .then_with(|| left.receipt_digest.cmp(&right.receipt_digest))
        });
        Self {
            tenant_id: tenant_id.into(),
            source_id: source_id.into(),
            family_id: family_id.into(),
            source_runtime_id: source_runtime_id.into(),
            runtime_revision_sha256: runtime_revision_sha256.into(),
            reasons,
            receipts,
        }
    }

    pub(crate) fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub(crate) fn source_id(&self) -> &str {
        &self.source_id
    }

    pub(crate) fn family_id(&self) -> &str {
        &self.family_id
    }

    pub(crate) fn source_runtime_id(&self) -> &str {
        &self.source_runtime_id
    }

    pub(crate) fn runtime_revision_sha256(&self) -> &str {
        &self.runtime_revision_sha256
    }

    pub(crate) fn reasons(&self) -> &[String] {
        &self.reasons
    }

    pub(crate) fn receipts(&self) -> &[VerifiedPromotionReceipt] {
        &self.receipts
    }

    pub(crate) fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("promotion verification serializes");
        let digest = Sha256::digest(bytes);
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl PostgresLedger {
    pub(crate) async fn verify_projection_promotion_evidence(
        &self,
        request: &ProjectionPromotionRequest,
    ) -> Result<PromotionEvidenceVerification, StoreError> {
        let qualification = request.qualification();
        let mut reasons = Vec::new();
        let mut receipts = Vec::new();
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        super::postgres::set_tenant(&transaction, request.tenant_id()).await?;

        let collection = &qualification.authenticated_collection_receipt;
        let collection_row = transaction
            .query_opt(
                "SELECT source_runtime_id, source_id, status, pages_read, records_accepted, records_rejected, entities_projected, links_projected, manifest_digest, manifest_json FROM organizational_source_collection_receipts WHERE tenant_id = $1 AND collection_id = $2",
                &[&request.tenant_id(), &collection.collection_id],
            )
            .await?;
        match collection_row {
            Some(row) => {
                let source_runtime_id: String = row.get(0);
                let source_id: String = row.get(1);
                let status: String = row.get(2);
                let pages_read: i64 = row.get(3);
                let records_accepted: i64 = row.get(4);
                let records_rejected: i64 = row.get(5);
                let entities_projected: i64 = row.get(6);
                let links_projected: i64 = row.get(7);
                let manifest_digest: String = row.get(8);
                let manifest: Value = row.get(9);
                let observed_family = manifest
                    .get("observed_family_ids")
                    .and_then(Value::as_array)
                    .is_some_and(|families| {
                        families
                            .iter()
                            .any(|family| family.as_str() == Some(request.family_id()))
                    });
                if let Some(reason) = collection_block_reason(
                    request.source_id(),
                    collection,
                    &source_runtime_id,
                    &source_id,
                    &status,
                    pages_read,
                    records_accepted,
                    records_rejected,
                    entities_projected,
                    links_projected,
                    &manifest_digest,
                    observed_family,
                ) {
                    reasons.push(reason);
                } else {
                    receipts.push(VerifiedPromotionReceipt::new(
                        VerifiedPromotionReceiptKind::DurableCollection,
                        collection.collection_id.clone(),
                        manifest_digest.clone(),
                    ));
                }
                if let Some(reason) = authenticated_collection_block_reason(
                    &manifest,
                    &qualification.supported_auth_modes,
                    &qualification.credential_lease_mode,
                ) {
                    reasons.push(reason);
                } else {
                    receipts.push(VerifiedPromotionReceipt::new(
                        VerifiedPromotionReceiptKind::AuthenticatedCollection,
                        collection.collection_id.clone(),
                        manifest_digest,
                    ));
                }
            }
            None => reasons.push("persisted collection receipt was not found".to_owned()),
        }

        verify_page_reference(
            &transaction,
            request,
            &qualification.append_projection_checkpoint_receipt,
            VerifiedPromotionReceiptKind::AppendProjectionCheckpoint,
            "append_projection_checkpoint",
            false,
            &mut reasons,
            &mut receipts,
        )
        .await?;
        verify_page_reference(
            &transaction,
            request,
            &qualification.lease_restart_receipt,
            VerifiedPromotionReceiptKind::LeaseRestart,
            "lease_restart",
            true,
            &mut reasons,
            &mut receipts,
        )
        .await?;

        let source_runtime_row = transaction
            .query_opt(
                "SELECT runtime_json FROM source_runtimes WHERE id = $1 AND runtime_json->>'tenant_id' = $2 AND runtime_json->>'source_id' = $3",
                &[
                    &collection.source_runtime_id,
                    &request.tenant_id(),
                    &request.source_id(),
                ],
            )
            .await?;
        match source_runtime_row {
            Some(row) => {
                let runtime_json: Value = row.get(0);
                if let Some(reason) = runtime_revision_block_reason(
                    &runtime_json,
                    &qualification.runtime_revision_sha256,
                    &qualification.worker_runtime_build_identity,
                ) {
                    reasons.push(reason);
                } else {
                    receipts.push(VerifiedPromotionReceipt::new(
                        VerifiedPromotionReceiptKind::RuntimeRevision,
                        qualification.runtime_revision_sha256.clone(),
                        qualification.runtime_revision_sha256.clone(),
                    ));
                }
            }
            None => reasons.push("persisted source runtime was not found".to_owned()),
        }

        verify_promotion_evidence_receipt(
            &transaction,
            request,
            &qualification.product_read_receipt,
            VerifiedPromotionReceiptKind::ProductRead,
            PromotionEvidenceReceiptKind::ProductRead,
            "product-read",
            &mut reasons,
            &mut receipts,
        )
        .await?;
        verify_promotion_evidence_receipt(
            &transaction,
            request,
            &qualification.promotion_receipt,
            VerifiedPromotionReceiptKind::PromotionApproval,
            PromotionEvidenceReceiptKind::PromotionApproval,
            "promotion approval",
            &mut reasons,
            &mut receipts,
        )
        .await?;
        verify_promotion_evidence_receipt(
            &transaction,
            request,
            &qualification.rollback_receipt,
            VerifiedPromotionReceiptKind::Recovery,
            PromotionEvidenceReceiptKind::Rollback,
            "rollback",
            &mut reasons,
            &mut receipts,
        )
        .await?;

        let evidence_references = [
            &qualification.product_read_receipt,
            &qualification.promotion_receipt,
            &qualification.rollback_receipt,
        ];
        let distinct_ids = evidence_references
            .iter()
            .map(|reference| reference.receipt_id.as_str())
            .collect::<BTreeSet<_>>();
        let distinct_digests = evidence_references
            .iter()
            .map(|reference| reference.receipt_digest_sha256.as_str())
            .collect::<BTreeSet<_>>();
        if distinct_ids.len() != evidence_references.len()
            || distinct_digests.len() != evidence_references.len()
        {
            reasons.push(
                "promotion evidence receipts must reference distinct persisted records".to_owned(),
            );
        }

        let parity_rows = transaction
            .query(
                "SELECT receipt_digest FROM organizational_parity_receipts WHERE tenant_id = $1 AND source_id = $2 AND family_id = $3 AND receipt_digest = ANY($4::TEXT[])",
                &[
                    &request.tenant_id(),
                    &request.source_id(),
                    &request.family_id(),
                    &qualification.parity_receipt_digests,
                ],
            )
            .await?;
        let found_parity = parity_rows
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<BTreeSet<_>>();
        let expected_parity = qualification
            .parity_receipt_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if found_parity != expected_parity {
            reasons
                .push("persisted parity receipts do not match the qualified sequence".to_owned());
        } else {
            receipts.extend(found_parity.into_iter().map(|digest| {
                VerifiedPromotionReceipt::new(
                    VerifiedPromotionReceiptKind::Parity,
                    digest.clone(),
                    digest,
                )
            }));
        }

        transaction.commit().await?;
        Ok(PromotionEvidenceVerification::verified_by_store(
            request.tenant_id(),
            request.source_id(),
            request.family_id(),
            &qualification
                .authenticated_collection_receipt
                .source_runtime_id,
            &qualification.runtime_revision_sha256,
            reasons,
            receipts,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn verify_page_reference(
    transaction: &tokio_postgres::Transaction<'_>,
    request: &ProjectionPromotionRequest,
    reference: &PagePublicationReceiptReference,
    kind: VerifiedPromotionReceiptKind,
    kind_label: &str,
    require_successor_generation: bool,
    reasons: &mut Vec<String>,
    receipts: &mut Vec<VerifiedPromotionReceipt>,
) -> Result<(), StoreError> {
    let row = transaction
        .query_opt(
            "SELECT source_runtime_id, source_id, family_id, state, revision, publication_json FROM source_runtime_page_publications WHERE tenant_id = $1 AND logical_page_id = $2",
            &[&request.tenant_id(), &reference.logical_page_id],
        )
        .await?;
    let Some(row) = row else {
        reasons.push(format!(
            "persisted {kind_label} page publication was not found"
        ));
        return Ok(());
    };
    let source_runtime_id: String = row.get(0);
    let source_id: String = row.get(1);
    let family_id: String = row.get(2);
    let state: String = row.get(3);
    let revision: i64 = row.get(4);
    let snapshot: Value = row.get(5);
    let snapshot_digest = json_digest(&snapshot);
    let page = PagePublication::restore_snapshot(snapshot).map_err(|_| {
        StoreError::Conflict(format!("stored {kind_label} page publication is invalid"))
    })?;
    let revision_matches = u64::try_from(revision).ok() == Some(reference.revision);
    let claim_generation = page.publish_claim().map(|claim| claim.generation());
    if let Some(reason) = page_block_reason(
        request.source_id(),
        request.family_id(),
        reference,
        &source_runtime_id,
        &source_id,
        &family_id,
        &state,
        page.state(),
        revision_matches,
        &snapshot_digest,
        require_successor_generation,
        claim_generation,
    ) {
        reasons.push(reason.replace("{kind}", kind_label));
    } else {
        receipts.push(VerifiedPromotionReceipt::new(
            kind,
            reference.logical_page_id.clone(),
            snapshot_digest,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collection_block_reason(
    request_source_id: &str,
    reference: &cerebro_source_catalog::SourceCollectionReceiptReference,
    stored_runtime_id: &str,
    stored_source_id: &str,
    status: &str,
    pages_read: i64,
    records_accepted: i64,
    records_rejected: i64,
    entities_projected: i64,
    links_projected: i64,
    stored_manifest_digest: &str,
    observed_family: bool,
) -> Option<String> {
    if stored_runtime_id != reference.source_runtime_id {
        Some("collection receipt runtime does not match qualification".to_owned())
    } else if stored_source_id != request_source_id {
        Some("collection receipt source does not match promotion request".to_owned())
    } else if status != "complete" {
        Some("collection receipt is not complete".to_owned())
    } else if pages_read <= 0 || records_accepted <= 0 {
        Some("collection receipt does not prove accepted provider records".to_owned())
    } else if records_rejected != 0 {
        Some("collection receipt contains rejected records".to_owned())
    } else if entities_projected <= 0 && links_projected <= 0 {
        Some("collection receipt does not prove a durable projection".to_owned())
    } else if stored_manifest_digest != reference.manifest_digest_sha256 {
        Some("collection manifest digest does not match qualification".to_owned())
    } else if !observed_family {
        Some("collection receipt does not include the promoted family".to_owned())
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn page_block_reason(
    request_source_id: &str,
    request_family_id: &str,
    reference: &PagePublicationReceiptReference,
    stored_runtime_id: &str,
    stored_source_id: &str,
    stored_family_id: &str,
    stored_state: &str,
    page_state: PagePublicationState,
    revision_matches: bool,
    snapshot_digest: &str,
    require_successor_generation: bool,
    claim_generation: Option<u64>,
) -> Option<String> {
    if stored_runtime_id != reference.source_runtime_id {
        Some("{kind} page runtime does not match qualification".to_owned())
    } else if stored_source_id != request_source_id || stored_family_id != request_family_id {
        Some("{kind} page source family does not match promotion request".to_owned())
    } else if stored_state != "committed" || page_state != PagePublicationState::Committed {
        Some("{kind} page did not commit append projection and checkpoint".to_owned())
    } else if !revision_matches {
        Some("{kind} page revision is stale".to_owned())
    } else if snapshot_digest != reference.snapshot_digest_sha256 {
        Some("{kind} page snapshot digest does not match qualification".to_owned())
    } else if require_successor_generation
        && claim_generation.is_none_or(|generation| generation <= 1)
    {
        Some("lease/restart page does not prove a successor generation".to_owned())
    } else {
        None
    }
}

fn authenticated_collection_block_reason(
    manifest: &Value,
    supported_auth_modes: &[String],
    credential_lease_mode: &str,
) -> Option<String> {
    let Some(proof) = manifest.get("authenticated_request_proof") else {
        return Some(
            "authenticated collection manifest does not include an authenticated request proof"
                .to_owned(),
        );
    };
    let Some(auth_mode) = proof
        .get("auth_mode")
        .and_then(Value::as_str)
        .filter(|mode| !mode.trim().is_empty())
    else {
        return Some("authenticated request proof does not include an auth mode".to_owned());
    };
    if !supported_auth_modes.iter().any(|mode| mode == auth_mode) {
        return Some(
            "authenticated request proof auth mode does not match qualification".to_owned(),
        );
    }
    let Some(lease_mode) = proof.get("credential_lease_mode").and_then(Value::as_str) else {
        return Some(
            "authenticated request proof does not include a credential lease mode".to_owned(),
        );
    };
    if lease_mode != credential_lease_mode {
        return Some(
            "authenticated request proof credential lease mode does not match qualification"
                .to_owned(),
        );
    }
    None
}

fn runtime_revision_block_reason(
    runtime_json: &Value,
    runtime_revision_sha256: &str,
    worker_runtime_build_identity: &str,
) -> Option<String> {
    let Some(stored_revision) = runtime_json
        .get("runtime_revision_sha256")
        .and_then(Value::as_str)
    else {
        return Some("stored source runtime does not record a runtime revision".to_owned());
    };
    if stored_revision != runtime_revision_sha256 {
        return Some("stored source runtime revision does not match qualification".to_owned());
    }
    let Some(stored_identity) = runtime_json
        .get("worker_runtime_build_identity")
        .and_then(Value::as_str)
    else {
        return Some("stored source runtime does not record a worker build identity".to_owned());
    };
    if stored_identity != worker_runtime_build_identity {
        return Some(
            "stored source runtime build identity does not match qualification".to_owned(),
        );
    }
    None
}

#[allow(clippy::too_many_arguments)]
async fn verify_promotion_evidence_receipt(
    transaction: &tokio_postgres::Transaction<'_>,
    request: &ProjectionPromotionRequest,
    reference: &PersistedReceiptReference,
    kind: VerifiedPromotionReceiptKind,
    stored_kind: PromotionEvidenceReceiptKind,
    kind_label: &str,
    reasons: &mut Vec<String>,
    receipts: &mut Vec<VerifiedPromotionReceipt>,
) -> Result<(), StoreError> {
    let row = transaction
        .query_opt(
            "SELECT source_id, family_id, receipt_digest FROM organizational_promotion_evidence_receipts WHERE tenant_id = $1 AND kind = $2 AND receipt_id = $3",
            &[
                &request.tenant_id(),
                &stored_kind.as_str(),
                &reference.receipt_id,
            ],
        )
        .await?;
    let Some(row) = row else {
        reasons.push(format!("persisted {kind_label} receipt was not found"));
        return Ok(());
    };
    let source_id: String = row.get(0);
    let family_id: String = row.get(1);
    let receipt_digest: String = row.get(2);
    if source_id != request.source_id() || family_id != request.family_id() {
        reasons.push(format!(
            "persisted {kind_label} receipt does not match promotion request"
        ));
    } else if receipt_digest != reference.receipt_digest_sha256 {
        reasons.push(format!(
            "persisted {kind_label} receipt digest does not match qualification"
        ));
    } else {
        receipts.push(VerifiedPromotionReceipt::new(
            kind,
            reference.receipt_id.clone(),
            receipt_digest,
        ));
    }
    Ok(())
}

pub(crate) fn json_digest(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("JSON value serializes");
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "promotion_evidence_test_support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "promotion_evidence_store_tests.rs"]
mod tests;
