use std::collections::{BTreeMap, BTreeSet};

use cerebro_platform_sdk::{
    AssertionId, ContentDigest, EntityId, GraphChange, GraphChangeKind, GraphDiff,
    GraphDiffRequest, GraphRevision, RevisionSelector, SdkError, TenantId,
};
use serde::Serialize;

use crate::canonical;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum SnapshotKey {
    Entity(EntityId),
    Assertion(AssertionId),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SnapshotValue {
    pub digest: ContentDigest,
    pub observed_at_unix_millis: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RevisionSnapshot {
    pub tenant_id: TenantId,
    pub revision: GraphRevision,
    pub values: BTreeMap<SnapshotKey, SnapshotValue>,
}

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
