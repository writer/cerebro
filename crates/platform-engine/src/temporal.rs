//! Pure, deterministic diffing for two fully materialized graph revisions.
//!
//! This module compares caller-supplied endpoint snapshots; it does not load
//! revisions, prove snapshot completeness, or resolve graph authority. It owns
//! stable change ordering, full-result digesting, and digest-bound pagination.

use std::collections::{BTreeMap, BTreeSet};

use cerebro_platform_sdk::{
    AssertionId, ContentDigest, EntityId, GraphChange, GraphChangeKind, GraphDiff,
    GraphDiffRequest, GraphRevision, RevisionSelector, SdkError, TenantId,
};
use serde::Serialize;

use crate::canonical;

/// Ordered identity of a value in a revision snapshot.
///
/// Derived ordering places all entity keys before assertion keys and then uses
/// each typed identifier's lexical order. That order is part of deterministic
/// diff hashing and pagination.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum SnapshotKey {
    /// Entity state keyed by stable entity identity.
    Entity(EntityId),
    /// Assertion state keyed by stable assertion identity.
    Assertion(AssertionId),
}

/// Digest and observation time for one value at one graph revision.
///
/// Diff equality is digest-based: changing only the observation time does not
/// produce a [`GraphChange`]. Snapshot construction must therefore ensure the
/// digest covers every semantic field that should count as an update.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SnapshotValue {
    /// Digest of the target's canonical content at this revision.
    pub digest: ContentDigest,
    /// Unix-millisecond observation time carried into an emitted change.
    pub observed_at_unix_millis: i64,
}

/// Fully materialized digest view of one tenant graph revision.
///
/// The ordered map guarantees stable iteration but does not prove completeness,
/// tenant ownership of its keys, or correspondence to durable graph state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RevisionSnapshot {
    /// Tenant asserted to own every value in the snapshot.
    pub tenant_id: TenantId,
    /// Logical graph revision represented by the values.
    pub revision: GraphRevision,
    /// At most one digest record for each typed graph target.
    pub values: BTreeMap<SnapshotKey, SnapshotValue>,
}

/// Computes a digest-bound page of changes between two revision snapshots.
///
/// The function first validates tenant and revision bindings, then compares the
/// union of keys in deterministic [`SnapshotKey`] order. It hashes the complete
/// ordered change set before applying the requested page, so a continuation
/// cannot be replayed against a different semantic diff. An exact ending
/// selector must equal `after.revision`; a current selector is concretized to
/// that revision in the returned [`GraphDiff`].
///
/// An offset equal to the result length is a valid terminal continuation and
/// returns an empty, non-truncated page. This function has no I/O and does not
/// establish that either caller-supplied snapshot is authoritative or complete.
///
/// # Errors
///
/// Returns request validation errors, [`SdkError::Invalid`] for a tenant,
/// revision, or cursor binding mismatch, [`SdkError::OutOfRange`] if the page
/// limit cannot be represented on the current platform, or [`SdkError::Backend`]
/// if canonical serialization of the complete diff fails.
pub fn diff_snapshots(
    request: &GraphDiffRequest,
    before: &RevisionSnapshot,
    after: &RevisionSnapshot,
) -> Result<GraphDiff, SdkError> {
    request.validate()?;
    if request.tenant_id != before.tenant_id || request.tenant_id != after.tenant_id {
        return Err(SdkError::Invalid("graph diff tenant"));
    }
    if request.from_revision != before.revision {
        return Err(SdkError::Invalid("graph diff starting revision"));
    }
    if let RevisionSelector::Exact(revision) = request.to_revision
        && revision != after.revision
    {
        return Err(SdkError::Invalid("graph diff ending revision"));
    }
    if after.revision <= before.revision {
        return Err(SdkError::Invalid("graph diff revision window"));
    }

    // A sorted union supplies one stable traversal across additions, updates,
    // and retractions regardless of either map's construction history.
    let keys = before
        .values
        .keys()
        .chain(after.values.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut changes = keys
        .into_iter()
        .filter_map(|key| change_for_key(&key, before.values.get(&key), after.values.get(&key)))
        .collect::<Vec<_>>();

    // Bind pagination to the entire semantic result. Page size and cursor
    // offset are deliberately absent so every page advertises the same digest.
    let full_digest = canonical::digest(&(
        &request.tenant_id,
        before.revision,
        after.revision,
        &changes,
    ))?;
    let offset = parse_cursor(request.cursor.as_deref(), &full_digest)?;
    if offset > changes.len() {
        return Err(SdkError::Invalid("graph diff cursor"));
    }
    let limit =
        usize::try_from(request.limit).map_err(|_| SdkError::OutOfRange("graph diff limit"))?;
    let remaining = changes.len() - offset;
    let page_len = remaining.min(limit);
    let page = changes.drain(offset..offset + page_len).collect::<Vec<_>>();
    let next_offset = offset + page_len;
    let truncated = next_offset < offset + remaining;

    // Cursors contain no tenant or revision fields because the digest already
    // commits to both endpoints and the tenant alongside every ordered change.
    let next_cursor = truncated.then(|| format!("{next_offset}:{full_digest}"));
    Ok(GraphDiff {
        tenant_id: request.tenant_id.clone(),
        from_revision: before.revision,
        to_revision: after.revision,
        changes: page,
        next_cursor,
        truncated,
        digest: full_digest,
    })
}

/// Parses an engine cursor and verifies its full-diff digest binding.
///
/// Tokens use the internal `<offset>:<digest>` representation. The surrounding
/// request validator bounds token length before this parser performs any work.
fn parse_cursor(cursor: Option<&str>, digest: &ContentDigest) -> Result<usize, SdkError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let (offset, binding) = cursor
        .split_once(':')
        .ok_or(SdkError::Invalid("graph diff cursor"))?;
    if binding != digest.as_str() {
        return Err(SdkError::Invalid("graph diff cursor"));
    }
    offset
        .parse()
        .map_err(|_| SdkError::Invalid("graph diff cursor"))
}

/// Converts one differing snapshot entry into its typed change contract.
///
/// Additions and updates take the after timestamp; retractions preserve the
/// before timestamp. Equal digests produce no change even if timestamps differ.
fn change_for_key(
    key: &SnapshotKey,
    before: Option<&SnapshotValue>,
    after: Option<&SnapshotValue>,
) -> Option<GraphChange> {
    if before.map(|value| &value.digest) == after.map(|value| &value.digest) {
        return None;
    }
    let (entity_id, assertion_id, added, updated, retracted) = match key {
        SnapshotKey::Entity(id) => (
            Some(id.clone()),
            None,
            GraphChangeKind::EntityAdded,
            GraphChangeKind::EntityUpdated,
            GraphChangeKind::EntityRetracted,
        ),
        SnapshotKey::Assertion(id) => (
            None,
            Some(id.clone()),
            GraphChangeKind::AssertionAdded,
            GraphChangeKind::AssertionUpdated,
            GraphChangeKind::AssertionRetracted,
        ),
    };
    let kind = match (before, after) {
        (None, Some(_)) => added,
        (Some(_), Some(_)) => updated,
        (Some(_), None) => retracted,
        (None, None) => return None,
    };
    Some(GraphChange {
        kind,
        entity_id,
        assertion_id,
        before_digest: before.map(|value| value.digest.clone()),
        after_digest: after.map(|value| value.digest.clone()),
        observed_at_unix_millis: after
            .or(before)
            .map_or(0, |value| value.observed_at_unix_millis),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_must_be_bound_to_the_current_snapshot_diff_digest() {
        let before = RevisionSnapshot {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            revision: GraphRevision::new(1).unwrap(),
            values: BTreeMap::new(),
        };
        let after = RevisionSnapshot {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            revision: GraphRevision::new(2).unwrap(),
            values: BTreeMap::new(),
        };
        let request = GraphDiffRequest {
            tenant_id: TenantId::parse("tenant-a").unwrap(),
            from_revision: GraphRevision::new(1).unwrap(),
            to_revision: RevisionSelector::Exact(GraphRevision::new(2).unwrap()),
            limit: 1,
            cursor: Some("0:stale-digest".to_owned()),
        };

        assert_eq!(
            diff_snapshots(&request, &before, &after),
            Err(SdkError::Invalid("graph diff cursor"))
        );
    }
}
