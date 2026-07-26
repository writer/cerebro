use serde::Serialize;

use crate::{AssertionId, ContentDigest, EntityId, SdkError, TenantId};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GraphRevision(u64);

impl GraphRevision {
    pub fn new(value: u64) -> Result<Self, SdkError> {
        if value == 0 {
            return Err(SdkError::OutOfRange("graph revision"));
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionSelector {
    Current,
    Exact(GraphRevision),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphChangeKind {
    EntityAdded,
    EntityUpdated,
    EntityRetracted,
    AssertionAdded,
    AssertionUpdated,
    AssertionRetracted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GraphChange {
    pub kind: GraphChangeKind,
    pub entity_id: Option<EntityId>,
    pub assertion_id: Option<AssertionId>,
    pub before_digest: Option<ContentDigest>,
    pub after_digest: Option<ContentDigest>,
    pub observed_at_unix_millis: i64,
}

impl GraphChange {
    pub fn validate(&self) -> Result<(), SdkError> {
        let entity_change = matches!(
            self.kind,
            GraphChangeKind::EntityAdded
                | GraphChangeKind::EntityUpdated
                | GraphChangeKind::EntityRetracted
        );
        if entity_change != self.entity_id.is_some() || entity_change == self.assertion_id.is_some()
        {
            return Err(SdkError::Invalid("graph change target"));
        }
        match self.kind {
            GraphChangeKind::EntityAdded | GraphChangeKind::AssertionAdded => {
                if self.before_digest.is_some() || self.after_digest.is_none() {
                    return Err(SdkError::Invalid("graph change digest"));
                }
            }
            GraphChangeKind::EntityUpdated | GraphChangeKind::AssertionUpdated => {
                if self.before_digest.is_none() || self.after_digest.is_none() {
                    return Err(SdkError::Invalid("graph change digest"));
                }
            }
            GraphChangeKind::EntityRetracted | GraphChangeKind::AssertionRetracted => {
                if self.before_digest.is_none() || self.after_digest.is_some() {
                    return Err(SdkError::Invalid("graph change digest"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GraphDiffRequest {
    pub tenant_id: TenantId,
    pub from_revision: GraphRevision,
    pub to_revision: RevisionSelector,
    pub limit: u32,
    pub cursor: Option<String>,
}

impl GraphDiffRequest {
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.limit == 0 || self.limit > 500 {
            return Err(SdkError::OutOfRange("graph diff limit"));
        }
        if let RevisionSelector::Exact(to_revision) = self.to_revision
            && to_revision <= self.from_revision
        {
            return Err(SdkError::Invalid("graph diff revision window"));
        }
        if self
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 512)
        {
            return Err(SdkError::Invalid("graph diff cursor"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GraphDiff {
    pub tenant_id: TenantId,
    pub from_revision: GraphRevision,
    pub to_revision: GraphRevision,
    pub changes: Vec<GraphChange>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
    pub digest: ContentDigest,
}
