//! Durable platform-event subscription contracts.
//!
//! Subscriptions select events within a tenant-scoped stream and resume from a
//! sequence cursor. These transport types do not authorize tenant access,
//! persist cursor progress, or verify payload content against its digest.

use serde::Serialize;
use std::collections::BTreeSet;

use crate::{
    AssertionDefinitionId, ContentDigest, EntityId, EntityKind, GraphRevision, SdkError,
    SubscriptionId, TenantId,
};

/// Coarse platform transition that can be selected by a subscription.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformEventKind {
    /// Materialized graph content or revision state changed.
    GraphChanged,
    /// An assertion's definition or evaluated state changed.
    AssertionChanged,
    /// Previously admitted evidence crossed its freshness boundary.
    EvidenceBecameStale,
    /// A mission's declared wake condition became satisfied.
    MissionWakeConditionMet,
    /// An action proposal or execution state changed.
    ActionChanged,
    /// Reported projection lag changed.
    ProjectionLagChanged,
}

/// Position in a durable, ordered platform-event stream.
///
/// Zero is a valid representable value. Construction does not prove that the
/// sequence exists, belongs to a tenant, or is still retained; the stream
/// implementation validates those properties when reading.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DurableCursor(u64);

impl DurableCursor {
    /// Wraps a stream sequence without consulting durable storage.
    pub fn new(sequence: u64) -> Self {
        Self(sequence)
    }

    /// Returns the represented stream sequence.
    pub fn sequence(self) -> u64 {
        self.0
    }
}

/// Conjunctive filter over platform-event dimensions.
///
/// Values within one vector are alternatives; populated dimensions are joined
/// with logical AND. An empty vector is a wildcard for that dimension, although
/// a persisted [`SubscriptionDefinition`] must constrain at least one dimension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubscriptionEventFilter {
    /// Accepted coarse event kinds.
    pub event_kinds: Vec<PlatformEventKind>,
    /// Accepted entity kinds for events that carry an entity kind.
    pub entity_kinds: Vec<EntityKind>,
    /// Accepted entity identities for events that carry an entity identity.
    pub entity_ids: Vec<EntityId>,
    /// Accepted assertion definitions for events that carry an assertion identity.
    pub assertion_ids: Vec<AssertionDefinitionId>,
}

impl SubscriptionEventFilter {
    /// Returns whether every filter dimension is unconstrained.
    ///
    /// This is a structural predicate, not an event-matching operation.
    pub fn is_empty(&self) -> bool {
        self.event_kinds.is_empty()
            && self.entity_kinds.is_empty()
            && self.entity_ids.is_empty()
            && self.assertion_ids.is_empty()
    }
}

/// Validated definition of a tenant-scoped durable subscription.
///
/// Filter value order is preserved. The validator rejects duplicates but does
/// not sort values or recompute [`Self::definition_digest`], so the definition
/// assembly boundary owns canonicalization and digest binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubscriptionDefinition {
    /// Stable identity of the subscription.
    pub subscription_id: SubscriptionId,
    /// Tenant whose already-scoped event stream is eligible for matching.
    pub tenant_id: TenantId,
    /// At-least-one-dimension event selection.
    pub filter: SubscriptionEventFilter,
    /// Maximum events requested per page, in the inclusive range `1..=500`.
    pub batch_limit: u16,
    /// Caller-supplied digest of the canonical subscription definition.
    pub definition_digest: ContentDigest,
}

impl SubscriptionDefinition {
    /// Validates filter presence, bounds, uniqueness, and batch size.
    ///
    /// The filter permits at most 6 event kinds, 29 entity kinds, 500 entity
    /// IDs, and 500 assertion IDs. This check does not authorize the tenant,
    /// bind IDs to tenant-owned objects, or verify the definition digest.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Empty`] for a fully unconstrained filter,
    /// [`SdkError::OutOfRange`] for an invalid batch limit or oversized filter,
    /// or [`SdkError::Conflict`] for a duplicate value within any dimension.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.filter.is_empty() {
            return Err(SdkError::Empty("subscription filter"));
        }
        if self.batch_limit == 0 || self.batch_limit > 500 {
            return Err(SdkError::OutOfRange("subscription batch limit"));
        }
        if self.filter.event_kinds.len() > 6
            || self.filter.entity_kinds.len() > 29
            || self.filter.entity_ids.len() > 500
            || self.filter.assertion_ids.len() > 500
        {
            return Err(SdkError::OutOfRange("subscription filter"));
        }
        if has_duplicates(&self.filter.event_kinds)
            || has_duplicates(&self.filter.entity_kinds)
            || has_duplicates(&self.filter.entity_ids)
            || has_duplicates(&self.filter.assertion_ids)
        {
            return Err(SdkError::Conflict(
                "duplicate subscription filter value".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Detects a repeated value without changing caller-supplied order.
fn has_duplicates<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

/// Immutable event delivered from a tenant-scoped durable stream.
///
/// Optional dimensions describe which filters can match the event. The SDK
/// type does not enforce kind-specific field presence or authenticate the
/// tenant, timestamp, sequence, or payload digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlatformEvent {
    /// Durable sequence assigned by the event stream.
    pub cursor: DurableCursor,
    /// Tenant asserted to own the event.
    pub tenant_id: TenantId,
    /// Coarse transition kind.
    pub kind: PlatformEventKind,
    /// Related graph revision, when the event is revision-bound.
    pub graph_revision: Option<GraphRevision>,
    /// Related entity kind, when applicable.
    pub entity_kind: Option<EntityKind>,
    /// Related entity identity, when applicable.
    pub entity_id: Option<EntityId>,
    /// Related assertion definition, when applicable.
    pub assertion_id: Option<AssertionDefinitionId>,
    /// Caller-supplied Unix-millisecond occurrence time.
    pub occurred_at_unix_millis: i64,
    /// Digest of the event payload stored or transported elsewhere.
    pub payload_digest: ContentDigest,
}

/// Bounded delivery page for one subscription.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubscriptionPage {
    /// Subscription whose filter produced this page.
    pub subscription_id: SubscriptionId,
    /// Ordered matching events, bounded by the definition's batch limit.
    pub events: Vec<PlatformEvent>,
    /// Cursor to pass to the next read, including for an empty page.
    pub next_cursor: DurableCursor,
    /// Whether the reader reached the event-stream head when the page was assembled.
    pub caught_up: bool,
}
