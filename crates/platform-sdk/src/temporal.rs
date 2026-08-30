//! Revision selectors and bounded change-page contracts for temporal graph reads.
//!
//! These types describe an ordered graph transition without loading revisions
//! or proving snapshot completeness. The engine binds requests to concrete
//! snapshots, constructs changes deterministically, and owns cursor issuance.

use serde::Serialize;

use crate::{AssertionId, ContentDigest, EntityId, SdkError, TenantId};

/// Non-zero logical revision of a tenant graph.
///
/// Revisions are comparable sequence markers. This wrapper does not require
/// adjacency, prove that a revision exists, or scope the number to a tenant;
/// the operation carrying it owns those checks.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GraphRevision(u64);

impl GraphRevision {
    /// Constructs a logical revision from a non-zero sequence value.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::OutOfRange`] when `value` is zero.
    pub fn new(value: u64) -> Result<Self, SdkError> {
        if value == 0 {
            return Err(SdkError::OutOfRange("graph revision"));
        }
        Ok(Self(value))
    }

    /// Returns the underlying sequence value.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Selects the ending revision for a temporal read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionSelector {
    /// Resolve the ending revision to the current graph head at execution time.
    Current,
    /// Require a specific ending revision.
    Exact(GraphRevision),
}

/// Semantic transition represented by one graph change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphChangeKind {
    /// An entity is absent before the window and present afterward.
    EntityAdded,
    /// An entity is present at both endpoints with different content digests.
    EntityUpdated,
    /// An entity is present before the window and absent afterward.
    EntityRetracted,
    /// An assertion is absent before the window and present afterward.
    AssertionAdded,
    /// An assertion is present at both endpoints with different content digests.
    AssertionUpdated,
    /// An assertion is present before the window and absent afterward.
    AssertionRetracted,
}

/// Digest-level change to exactly one entity or assertion.
///
/// Added changes carry only an after digest, updates carry both digests, and
/// retractions carry only a before digest. The observed timestamp comes from
/// the endpoint record that establishes the change and is not validated by the
/// SDK shape check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GraphChange {
    /// Target domain and transition type.
    pub kind: GraphChangeKind,
    /// Changed entity, present only for an entity change.
    pub entity_id: Option<EntityId>,
    /// Changed assertion, present only for an assertion change.
    pub assertion_id: Option<AssertionId>,
    /// Content digest at the starting revision, when the target existed there.
    pub before_digest: Option<ContentDigest>,
    /// Content digest at the ending revision, when the target exists there.
    pub after_digest: Option<ContentDigest>,
    /// Caller-supplied Unix-millisecond observation time for the endpoint value.
    pub observed_at_unix_millis: i64,
}

impl GraphChange {
    /// Validates the target and digest shape required by [`Self::kind`].
    ///
    /// This method does not verify either digest against graph content, validate
    /// the timestamp, or prove that the target belongs to the enclosing tenant.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Invalid`] when the change does not name exactly the
    /// target domain and digest endpoints implied by its kind.
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

/// Bounded request for changes after one graph revision.
///
/// Cursors are opaque to transport clients. The SDK validates only their size;
/// the engine validates their syntax and binds them to the complete diff.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GraphDiffRequest {
    /// Tenant whose revisions are being compared.
    pub tenant_id: TenantId,
    /// Exclusive logical starting point represented by the before snapshot.
    pub from_revision: GraphRevision,
    /// Ending revision selection resolved by the execution boundary.
    pub to_revision: RevisionSelector,
    /// Maximum number of changes to return, in the inclusive range `1..=500`.
    pub limit: u32,
    /// Engine-issued continuation token, bounded to 512 bytes when present.
    pub cursor: Option<String>,
}

impl GraphDiffRequest {
    /// Validates the page bound, explicit revision window, and cursor size.
    ///
    /// A [`RevisionSelector::Current`] window is validated after the current
    /// revision is resolved. Cursor content is intentionally left to the engine
    /// because it is bound to the digest of concrete endpoint snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::OutOfRange`] for a limit outside `1..=500`, or
    /// [`SdkError::Invalid`] for a non-increasing exact revision window or an
    /// empty or oversized cursor.
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

/// One deterministic page from a complete graph revision diff.
///
/// [`Self::digest`] identifies the complete ordered change set, not merely the
/// returned page. When [`Self::truncated`] is true, [`Self::next_cursor`] resumes
/// within that same digest-bound result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GraphDiff {
    /// Tenant shared by the request and both endpoint snapshots.
    pub tenant_id: TenantId,
    /// Concrete starting revision.
    pub from_revision: GraphRevision,
    /// Concrete ending revision, including a resolved `current` selection.
    pub to_revision: GraphRevision,
    /// Deterministically ordered changes in this page.
    pub changes: Vec<GraphChange>,
    /// Continuation token for the same complete diff, when another page exists.
    pub next_cursor: Option<String>,
    /// Whether additional changes remain after this page.
    pub truncated: bool,
    /// Content digest of the complete ordered diff before pagination.
    pub digest: ContentDigest,
}
