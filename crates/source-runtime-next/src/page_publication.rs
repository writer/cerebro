//! Fenced publication state for one durable source-runtime page.
//!
//! Provider collection does not authorize durable progress. This module keeps
//! the ordered append claim, append acknowledgements, projection receipt, and
//! terminal progress decision in one credential-free state machine so recovery
//! can resume the same page without recollecting provider data.

use std::{collections::BTreeSet, error::Error, fmt};

use cerebro_organizational_model::{ObservationId, SourceRuntimeId, TenantId};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_PAGE_EVENTS: usize = 100_000;
const MAX_ID_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 512;
const MESSAGE_ID_DOMAIN: &[u8] = b"cerebro.source-page-message/v1\0";

/// Unvalidated identity and fencing inputs for one logical page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagePublicationInput {
    /// Stable page identity reused across process restarts.
    pub logical_page_id: String,
    /// Tenant that owns every event and durable transition.
    pub tenant_id: TenantId,
    /// Stored runtime that collected the page.
    pub source_runtime_id: SourceRuntimeId,
    /// Catalog source identifier.
    pub source_id: String,
    /// Catalog family identifier.
    pub family_id: String,
    /// Runtime lease generation that admitted provider execution.
    pub lease_generation: u64,
    /// Source-family authority epoch that admitted provider execution.
    pub authority_epoch: u64,
    /// Digest of the exact provider request intent.
    pub request_intent_sha256: String,
    /// Digest of the input cursor and checkpoint state.
    pub input_progress_sha256: String,
    /// Digest of the proposed cursor and checkpoint state.
    pub target_progress_sha256: String,
    /// Digest of the complete deterministic page result.
    pub result_sha256: String,
}

/// One accepted event prepared for ordered append publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageEventInput {
    /// Stable event identity.
    pub event_id: ObservationId,
    /// Digest of the canonical append-log envelope bytes.
    pub envelope_sha256: String,
}

/// Monotonic ownership fence for publishing a prepared page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublishClaim {
    owner: String,
    generation: u64,
}

impl PublishClaim {
    /// Creates a positive-generation claim with a bounded owner identity.
    pub fn new(owner: impl Into<String>, generation: u64) -> Result<Self, PagePublicationError> {
        let owner = bounded_text(owner.into(), "publish claim owner", MAX_ID_BYTES)?;
        if generation == 0 {
            return Err(PagePublicationError::Invalid(
                "publish claim generation must be positive",
            ));
        }
        Ok(Self { owner, generation })
    }

    /// Returns the worker identity that owns publication.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the monotonic publish-claim generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Ordered event identity and idempotency metadata retained in the page outbox.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PageEventIntent {
    ordinal: u32,
    event_id: ObservationId,
    envelope_sha256: String,
    message_id: String,
}

impl PageEventIntent {
    /// Returns the zero-based order within the logical page.
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns the stable event identity.
    pub fn event_id(&self) -> &ObservationId {
        &self.event_id
    }

    /// Returns the digest of the exact append-log envelope bytes.
    pub fn envelope_sha256(&self) -> &str {
        &self.envelope_sha256
    }

    /// Returns the stable JetStream message identity used after unknown acknowledgements.
    pub fn message_id(&self) -> &str {
        &self.message_id
    }
}

/// Durable acknowledgement for one ordered append-log event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PageAppendReceipt {
    /// Zero-based page order acknowledged by the append log.
    pub ordinal: u32,
    /// Stable event identity acknowledged by the append log.
    pub event_id: ObservationId,
    /// Stable message identity sent with the append.
    pub message_id: String,
    /// JetStream stream that accepted the event.
    pub stream: String,
    /// Positive stream sequence returned by JetStream.
    pub stream_sequence: u64,
}

/// Durable projection result for the fully appended page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PageProjectionReceipt {
    /// Digest of the exact projection delta.
    pub delta_sha256: String,
    /// Durable graph revision produced by the projection transaction.
    pub graph_revision: u64,
}

/// Persistable source-page publication state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PagePublicationState {
    /// Events and target progress are durable but no publisher owns the page.
    Prepared,
    /// One fenced publisher owns ordered append work.
    Publishing,
    /// Every event has a durable append acknowledgement.
    Published,
    /// The fully published page has a durable projection receipt.
    Projected,
    /// Runtime progress committed after append and projection.
    Committed,
    /// A page with no acknowledged append was retired by a newer decision.
    Superseded,
    /// Recovery stopped on a bounded inconsistency requiring operator action.
    Quarantined,
}

/// Credential-free state required to resume or finish one logical page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PagePublication {
    logical_page_id: String,
    tenant_id: TenantId,
    source_runtime_id: SourceRuntimeId,
    source_id: String,
    family_id: String,
    lease_generation: u64,
    authority_epoch: u64,
    request_intent_sha256: String,
    input_progress_sha256: String,
    target_progress_sha256: String,
    result_sha256: String,
    events: Vec<PageEventIntent>,
    append_receipts: Vec<PageAppendReceipt>,
    publish_claim: Option<PublishClaim>,
    projection_receipt: Option<PageProjectionReceipt>,
    state: PagePublicationState,
    quarantine_reason: Option<String>,
}

impl PagePublication {
    /// Validates and prepares one durable page without granting publish authority.
    pub fn prepare(
        input: PagePublicationInput,
        events: Vec<PageEventInput>,
    ) -> Result<Self, PagePublicationError> {
        let logical_page_id = bounded_text(input.logical_page_id, "logical page id", MAX_ID_BYTES)?;
        let source_id = bounded_text(input.source_id, "source id", MAX_ID_BYTES)?;
        let family_id = bounded_text(input.family_id, "family id", MAX_ID_BYTES)?;
        if input.lease_generation == 0 || input.authority_epoch == 0 {
            return Err(PagePublicationError::Invalid(
                "lease generation and authority epoch must be positive",
            ));
        }
        let request_intent_sha256 = digest(input.request_intent_sha256, "request intent")?;
        let input_progress_sha256 = digest(input.input_progress_sha256, "input progress")?;
        let target_progress_sha256 = digest(input.target_progress_sha256, "target progress")?;
        let result_sha256 = digest(input.result_sha256, "page result")?;
        if events.len() > MAX_PAGE_EVENTS {
            return Err(PagePublicationError::Invalid("page event limit exceeded"));
        }
        let mut event_ids = BTreeSet::new();
        let mut intents = Vec::with_capacity(events.len());
        for (ordinal, event) in events.into_iter().enumerate() {
            if !event_ids.insert(event.event_id.clone()) {
                return Err(PagePublicationError::Invalid("duplicate page event id"));
            }
            let envelope_sha256 = digest(event.envelope_sha256, "event envelope")?;
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| PagePublicationError::Invalid("page event ordinal overflow"))?;
            let message_id =
                page_message_id(&logical_page_id, ordinal, &event.event_id, &envelope_sha256);
            intents.push(PageEventIntent {
                ordinal,
                event_id: event.event_id,
                envelope_sha256,
                message_id,
            });
        }
        Ok(Self {
            logical_page_id,
            tenant_id: input.tenant_id,
            source_runtime_id: input.source_runtime_id,
            source_id,
            family_id,
            lease_generation: input.lease_generation,
            authority_epoch: input.authority_epoch,
            request_intent_sha256,
            input_progress_sha256,
            target_progress_sha256,
            result_sha256,
            events: intents,
            append_receipts: Vec::new(),
            publish_claim: None,
            projection_receipt: None,
            state: PagePublicationState::Prepared,
            quarantine_reason: None,
        })
    }

    /// Returns the stable page identity.
    pub fn logical_page_id(&self) -> &str {
        &self.logical_page_id
    }

    /// Returns the current terminal or recovery state.
    pub fn state(&self) -> PagePublicationState {
        self.state
    }

    /// Returns the ordered event intents retained for recovery.
    pub fn events(&self) -> &[PageEventIntent] {
        &self.events
    }

    /// Returns append acknowledgements in page order.
    pub fn append_receipts(&self) -> &[PageAppendReceipt] {
        &self.append_receipts
    }

    /// Grants a publisher the first monotonic claim on a prepared page.
    pub fn begin_publishing(&mut self, claim: PublishClaim) -> Result<(), PagePublicationError> {
        match self.state {
            PagePublicationState::Prepared => {
                self.publish_claim = Some(claim);
                self.state = if self.events.is_empty() {
                    PagePublicationState::Published
                } else {
                    PagePublicationState::Publishing
                };
                Ok(())
            }
            PagePublicationState::Publishing if self.publish_claim.as_ref() == Some(&claim) => {
                Ok(())
            }
            _ => Err(PagePublicationError::InvalidTransition {
                from: self.state,
                operation: "begin publishing",
            }),
        }
    }

    /// Transfers unfinished publication to a strictly newer claim generation.
    pub fn transfer_claim(
        &mut self,
        current: &PublishClaim,
        successor: PublishClaim,
    ) -> Result<(), PagePublicationError> {
        self.require_claim(current)?;
        if !matches!(
            self.state,
            PagePublicationState::Publishing
                | PagePublicationState::Published
                | PagePublicationState::Projected
        ) || successor.generation <= current.generation
        {
            return Err(PagePublicationError::InvalidTransition {
                from: self.state,
                operation: "transfer publish claim",
            });
        }
        self.publish_claim = Some(successor);
        Ok(())
    }

    /// Records the next ordered append acknowledgement under the current claim.
    ///
    /// Repeating the exact receipt is idempotent, which covers an acknowledgement
    /// that reached the append log but was lost before the local commit.
    pub fn record_append(
        &mut self,
        claim: &PublishClaim,
        mut receipt: PageAppendReceipt,
    ) -> Result<(), PagePublicationError> {
        self.require_claim(claim)?;
        if !matches!(
            self.state,
            PagePublicationState::Publishing | PagePublicationState::Published
        ) {
            return Err(PagePublicationError::InvalidTransition {
                from: self.state,
                operation: "record append acknowledgement",
            });
        }
        receipt.message_id = bounded_text(receipt.message_id, "message id", MAX_ID_BYTES)?;
        receipt.stream = bounded_text(receipt.stream, "append stream", MAX_ID_BYTES)?;
        if receipt.stream_sequence == 0 {
            return Err(PagePublicationError::Invalid(
                "append stream sequence must be positive",
            ));
        }
        let ordinal = usize::try_from(receipt.ordinal)
            .map_err(|_| PagePublicationError::Invalid("append ordinal overflow"))?;
        let intent = self
            .events
            .get(ordinal)
            .ok_or(PagePublicationError::Invalid(
                "append ordinal is outside the page",
            ))?;
        if receipt.event_id != intent.event_id || receipt.message_id != intent.message_id {
            return Err(PagePublicationError::ReceiptMismatch);
        }
        if let Some(existing) = self.append_receipts.get(ordinal) {
            return if existing == &receipt {
                Ok(())
            } else {
                Err(PagePublicationError::ReceiptMismatch)
            };
        }
        if ordinal != self.append_receipts.len() {
            return Err(PagePublicationError::Invalid(
                "append acknowledgements must be recorded in page order",
            ));
        }
        self.append_receipts.push(receipt);
        if self.append_receipts.len() == self.events.len() {
            self.state = PagePublicationState::Published;
        }
        Ok(())
    }

    /// Records projection only after every page event has an append acknowledgement.
    pub fn record_projection(
        &mut self,
        claim: &PublishClaim,
        mut receipt: PageProjectionReceipt,
    ) -> Result<(), PagePublicationError> {
        self.require_claim(claim)?;
        if receipt.graph_revision == 0 {
            return Err(PagePublicationError::InvalidTransition {
                from: self.state,
                operation: "record projection",
            });
        }
        receipt.delta_sha256 = digest(receipt.delta_sha256, "projection delta")?;
        if self.state == PagePublicationState::Projected {
            return if self.projection_receipt.as_ref() == Some(&receipt) {
                Ok(())
            } else {
                Err(PagePublicationError::ReceiptMismatch)
            };
        }
        if self.state != PagePublicationState::Published {
            return Err(PagePublicationError::InvalidTransition {
                from: self.state,
                operation: "record projection",
            });
        }
        self.projection_receipt = Some(receipt);
        self.state = PagePublicationState::Projected;
        Ok(())
    }

    /// Marks progress committed only after append and projection receipts are durable.
    pub fn commit(&mut self, claim: &PublishClaim) -> Result<(), PagePublicationError> {
        self.require_claim(claim)?;
        if self.state == PagePublicationState::Committed {
            return Ok(());
        }
        if self.state != PagePublicationState::Projected || self.projection_receipt.is_none() {
            return Err(PagePublicationError::InvalidTransition {
                from: self.state,
                operation: "commit runtime progress",
            });
        }
        self.state = PagePublicationState::Committed;
        Ok(())
    }

    /// Retires a page only while no event has a durable append acknowledgement.
    pub fn supersede(&mut self) -> Result<(), PagePublicationError> {
        if !matches!(
            self.state,
            PagePublicationState::Prepared
                | PagePublicationState::Publishing
                | PagePublicationState::Published
        ) || !self.append_receipts.is_empty()
            || (self.state == PagePublicationState::Published && !self.events.is_empty())
        {
            return Err(PagePublicationError::InvalidTransition {
                from: self.state,
                operation: "supersede page",
            });
        }
        self.state = PagePublicationState::Superseded;
        Ok(())
    }

    /// Stops recovery with a bounded reason while preserving all receipts.
    pub fn quarantine(&mut self, reason: impl Into<String>) -> Result<(), PagePublicationError> {
        if matches!(
            self.state,
            PagePublicationState::Committed | PagePublicationState::Superseded
        ) {
            return Err(PagePublicationError::InvalidTransition {
                from: self.state,
                operation: "quarantine page",
            });
        }
        self.quarantine_reason = Some(bounded_text(
            reason.into(),
            "quarantine reason",
            MAX_REASON_BYTES,
        )?);
        self.state = PagePublicationState::Quarantined;
        Ok(())
    }

    fn require_claim(&self, claim: &PublishClaim) -> Result<(), PagePublicationError> {
        if self.publish_claim.as_ref() == Some(claim) {
            Ok(())
        } else {
            Err(PagePublicationError::StaleClaim)
        }
    }
}

/// A page publication input or transition failed closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PagePublicationError {
    /// A bounded input invariant was invalid.
    Invalid(&'static str),
    /// The requested operation is not valid from the current state.
    InvalidTransition {
        /// Current durable state.
        from: PagePublicationState,
        /// Requested state-machine operation.
        operation: &'static str,
    },
    /// The caller does not hold the current publish-claim generation.
    StaleClaim,
    /// An acknowledgement conflicts with the prepared event or stored receipt.
    ReceiptMismatch,
}

impl fmt::Display for PagePublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::InvalidTransition { from, operation } => {
                write!(formatter, "cannot {operation} from {from:?}")
            }
            Self::StaleClaim => formatter.write_str("publish claim is stale"),
            Self::ReceiptMismatch => formatter.write_str("append receipt does not match the page"),
        }
    }
}

impl Error for PagePublicationError {}

fn bounded_text(
    value: String,
    field: &'static str,
    maximum: usize,
) -> Result<String, PagePublicationError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(PagePublicationError::Invalid(field));
    }
    Ok(value)
}

fn digest(value: String, field: &'static str) -> Result<String, PagePublicationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(PagePublicationError::Invalid(field));
    }
    Ok(value)
}

fn page_message_id(
    logical_page_id: &str,
    ordinal: u32,
    event_id: &ObservationId,
    envelope_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MESSAGE_ID_DOMAIN);
    for field in [
        logical_page_id.as_bytes(),
        ordinal.to_string().as_bytes(),
        event_id.as_str().as_bytes(),
        envelope_sha256.as_bytes(),
    ] {
        hasher.update(field.len().to_be_bytes());
        hasher.update(field);
    }
    format!("cerebro-source-{digest:x}", digest = hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn prepared(event_ids: &[&str]) -> PagePublication {
        PagePublication::prepare(
            PagePublicationInput {
                logical_page_id: "page:runtime-a:users:1".to_owned(),
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("runtime-a").unwrap(),
                source_id: "okta".to_owned(),
                family_id: "users".to_owned(),
                lease_generation: 7,
                authority_epoch: 3,
                request_intent_sha256: DIGEST_A.to_owned(),
                input_progress_sha256: DIGEST_A.to_owned(),
                target_progress_sha256: DIGEST_B.to_owned(),
                result_sha256: DIGEST_B.to_owned(),
            },
            event_ids
                .iter()
                .map(|id| PageEventInput {
                    event_id: ObservationId::parse(*id).unwrap(),
                    envelope_sha256: DIGEST_A.to_owned(),
                })
                .collect(),
        )
        .unwrap()
    }

    fn receipt(page: &PagePublication, ordinal: usize, sequence: u64) -> PageAppendReceipt {
        let event = &page.events()[ordinal];
        PageAppendReceipt {
            ordinal: event.ordinal(),
            event_id: event.event_id().clone(),
            message_id: event.message_id().to_owned(),
            stream: "CEREBRO_EVENTS".to_owned(),
            stream_sequence: sequence,
        }
    }

    #[test]
    fn progress_cannot_commit_before_ordered_append_and_projection() {
        let mut page = prepared(&["event-a", "event-b"]);
        let claim = PublishClaim::new("worker-a", 1).unwrap();
        page.begin_publishing(claim.clone()).unwrap();
        assert_eq!(
            page.commit(&claim),
            Err(PagePublicationError::InvalidTransition {
                from: PagePublicationState::Publishing,
                operation: "commit runtime progress",
            })
        );
        let second = receipt(&page, 1, 2);
        assert_eq!(
            page.record_append(&claim, second.clone()),
            Err(PagePublicationError::Invalid(
                "append acknowledgements must be recorded in page order"
            ))
        );
        let first = receipt(&page, 0, 1);
        page.record_append(&claim, first).unwrap();
        page.record_append(&claim, second).unwrap();
        assert_eq!(page.state(), PagePublicationState::Published);
        page.record_projection(
            &claim,
            PageProjectionReceipt {
                delta_sha256: DIGEST_B.to_owned(),
                graph_revision: 9,
            },
        )
        .unwrap();
        page.commit(&claim).unwrap();
        assert_eq!(page.state(), PagePublicationState::Committed);
    }

    #[test]
    fn unknown_ack_retry_is_idempotent_but_conflicting_receipt_fails() {
        let mut page = prepared(&["event-a"]);
        let claim = PublishClaim::new("worker-a", 1).unwrap();
        page.begin_publishing(claim.clone()).unwrap();
        let acknowledged = receipt(&page, 0, 42);
        page.record_append(&claim, acknowledged.clone()).unwrap();
        page.record_append(&claim, acknowledged.clone()).unwrap();
        let mut conflicting = acknowledged;
        conflicting.stream_sequence = 43;
        assert_eq!(
            page.record_append(&claim, conflicting),
            Err(PagePublicationError::ReceiptMismatch)
        );
    }

    #[test]
    fn claim_transfer_fences_the_previous_publisher_without_losing_receipts() {
        let mut page = prepared(&["event-a", "event-b"]);
        let first = PublishClaim::new("worker-a", 1).unwrap();
        page.begin_publishing(first.clone()).unwrap();
        let first_receipt = receipt(&page, 0, 10);
        page.record_append(&first, first_receipt).unwrap();
        let successor = PublishClaim::new("worker-b", 2).unwrap();
        page.transfer_claim(&first, successor.clone()).unwrap();
        let second_receipt = receipt(&page, 1, 11);
        assert_eq!(
            page.record_append(&first, second_receipt.clone()),
            Err(PagePublicationError::StaleClaim)
        );
        page.record_append(&successor, second_receipt).unwrap();
        assert_eq!(page.append_receipts().len(), 2);
    }

    #[test]
    fn completed_append_and_projection_recovery_can_transfer_and_retry() {
        let mut page = prepared(&["event-a"]);
        let first = PublishClaim::new("worker-a", 1).unwrap();
        page.begin_publishing(first.clone()).unwrap();
        let append = receipt(&page, 0, 10);
        page.record_append(&first, append).unwrap();
        let successor = PublishClaim::new("worker-b", 2).unwrap();
        page.transfer_claim(&first, successor.clone()).unwrap();
        let projection = PageProjectionReceipt {
            delta_sha256: DIGEST_B.to_owned(),
            graph_revision: 9,
        };
        page.record_projection(&successor, projection.clone())
            .unwrap();
        page.record_projection(&successor, projection).unwrap();
        page.commit(&successor).unwrap();
        page.commit(&successor).unwrap();
        assert_eq!(page.state(), PagePublicationState::Committed);
    }

    #[test]
    fn supersede_is_allowed_only_before_the_first_append_acknowledgement() {
        let mut unappended = prepared(&["event-a"]);
        let claim = PublishClaim::new("worker-a", 1).unwrap();
        unappended.begin_publishing(claim.clone()).unwrap();
        unappended.supersede().unwrap();
        assert_eq!(unappended.state(), PagePublicationState::Superseded);

        let mut appended = prepared(&["event-a"]);
        appended.begin_publishing(claim.clone()).unwrap();
        let append = receipt(&appended, 0, 1);
        appended.record_append(&claim, append).unwrap();
        assert!(appended.supersede().is_err());
    }

    #[test]
    fn page_identity_rejects_duplicate_events_and_message_ids_are_stable() {
        let duplicate = PagePublication::prepare(
            PagePublicationInput {
                logical_page_id: "page-a".to_owned(),
                tenant_id: TenantId::parse("tenant-a").unwrap(),
                source_runtime_id: SourceRuntimeId::parse("runtime-a").unwrap(),
                source_id: "okta".to_owned(),
                family_id: "users".to_owned(),
                lease_generation: 1,
                authority_epoch: 1,
                request_intent_sha256: DIGEST_A.to_owned(),
                input_progress_sha256: DIGEST_A.to_owned(),
                target_progress_sha256: DIGEST_A.to_owned(),
                result_sha256: DIGEST_A.to_owned(),
            },
            vec![
                PageEventInput {
                    event_id: ObservationId::parse("event-a").unwrap(),
                    envelope_sha256: DIGEST_A.to_owned(),
                },
                PageEventInput {
                    event_id: ObservationId::parse("event-a").unwrap(),
                    envelope_sha256: DIGEST_A.to_owned(),
                },
            ],
        );
        assert_eq!(
            duplicate,
            Err(PagePublicationError::Invalid("duplicate page event id"))
        );
        let first = prepared(&["event-a"]);
        let second = prepared(&["event-a"]);
        assert_eq!(
            first.events()[0].message_id(),
            second.events()[0].message_id()
        );
    }
}
