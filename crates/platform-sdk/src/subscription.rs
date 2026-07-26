use serde::Serialize;
use std::collections::BTreeSet;

use crate::{
    AssertionDefinitionId, ContentDigest, EntityId, EntityKind, GraphRevision, SdkError,
    SubscriptionId, TenantId,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformEventKind {
    GraphChanged,
    AssertionChanged,
    EvidenceBecameStale,
    MissionWakeConditionMet,
    ActionChanged,
    ProjectionLagChanged,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DurableCursor(u64);

impl DurableCursor {
    pub fn new(sequence: u64) -> Self {
        Self(sequence)
    }

    pub fn sequence(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubscriptionEventFilter {
    pub event_kinds: Vec<PlatformEventKind>,
    pub entity_kinds: Vec<EntityKind>,
    pub entity_ids: Vec<EntityId>,
    pub assertion_ids: Vec<AssertionDefinitionId>,
}

impl SubscriptionEventFilter {
    pub fn is_empty(&self) -> bool {
        self.event_kinds.is_empty()
            && self.entity_kinds.is_empty()
            && self.entity_ids.is_empty()
            && self.assertion_ids.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubscriptionDefinition {
    pub subscription_id: SubscriptionId,
    pub tenant_id: TenantId,
    pub filter: SubscriptionEventFilter,
    pub batch_limit: u16,
    pub definition_digest: ContentDigest,
}

impl SubscriptionDefinition {
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

fn has_duplicates<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlatformEvent {
    pub cursor: DurableCursor,
    pub tenant_id: TenantId,
    pub kind: PlatformEventKind,
    pub graph_revision: Option<GraphRevision>,
    pub entity_kind: Option<EntityKind>,
    pub entity_id: Option<EntityId>,
    pub assertion_id: Option<AssertionDefinitionId>,
    pub occurred_at_unix_millis: i64,
    pub payload_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubscriptionPage {
    pub subscription_id: SubscriptionId,
    pub events: Vec<PlatformEvent>,
    pub next_cursor: DurableCursor,
    pub caught_up: bool,
}
