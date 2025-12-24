"""Shared Security Center primitives for entity and evidence modeling."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

EntityKind = str


@dataclass
class EntityProfile:
    kind: EntityKind
    entity_id: str
    name: str
    category: str | None = None
    tags: Sequence[str] = field(default_factory=list)
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass
class EvidenceArtifact:
    artifact_id: str
    entity_id: str
    source: str
    collected_at: datetime | None
    expires_at: datetime | None
    content_type: str | None = None
    labels: Sequence[str] = field(default_factory=list)
    metadata: Mapping[str, object] = field(default_factory=dict)


EvidenceLifecycleStatus = str


@dataclass
class EvidenceLifecycle:
    status: EvidenceLifecycleStatus
    age_days: int | None
    ttl_days: int | None
    next_refresh_at: datetime | None
    requires_action: bool


@dataclass
class LifecyclePolicy:
    max_age_days: int | None = None
    refresh_window_days: int | None = None
    hard_expiry_days: int | None = None


@dataclass
class EvidenceSetSummary:
    status: EvidenceLifecycleStatus
    lifecycle: Sequence[EvidenceLifecycle]
    stale_artifacts: Sequence[EvidenceArtifact]
    expired_artifacts: Sequence[EvidenceArtifact]
    next_refresh_at: datetime | None


def evaluate_evidence_lifecycle(
    artifact: EvidenceArtifact,
    policy: LifecyclePolicy,
    *,
    now: datetime | None = None,
) -> EvidenceLifecycle:
    now = now or datetime.utcnow()
    collected_at = artifact.collected_at
    expires_at = artifact.expires_at or _compute_expiry(
        collected_at, policy.hard_expiry_days, now
    )

    age_days = _compute_age_days(collected_at, now)
    ttl_days = _compute_ttl_days(collected_at, expires_at, policy.hard_expiry_days)

    status: EvidenceLifecycleStatus = "fresh"
    requires_action = False

    if expires_at and now >= expires_at:
        status = "expired"
        requires_action = True
    elif (
        policy.max_age_days is not None
        and age_days is not None
        and age_days > policy.max_age_days
    ):
        status = "stale"
        requires_action = True
    elif policy.refresh_window_days is not None and expires_at is not None:
        refresh_threshold = expires_at - timedelta(days=policy.refresh_window_days)
        if now >= refresh_threshold:
            status = "stale"
            requires_action = True

    return EvidenceLifecycle(
        status=status,
        age_days=age_days,
        ttl_days=ttl_days,
        next_refresh_at=expires_at,
        requires_action=requires_action,
    )


def summarize_evidence_set(
    artifacts: Sequence[EvidenceArtifact],
    policy: LifecyclePolicy,
    *,
    now: datetime | None = None,
) -> EvidenceSetSummary:
    now = now or datetime.utcnow()
    deduped = _dedupe_artifacts(artifacts)
    if not deduped:
        return EvidenceSetSummary(
            status="fresh",
            lifecycle=[],
            stale_artifacts=[],
            expired_artifacts=[],
            next_refresh_at=None,
        )

    lifecycle: list[EvidenceLifecycle] = []
    stale: list[EvidenceArtifact] = []
    expired: list[EvidenceArtifact] = []
    status: EvidenceLifecycleStatus = "fresh"
    next_refresh_at: datetime | None = None

    for artifact in deduped:
        item_lifecycle = evaluate_evidence_lifecycle(artifact, policy, now=now)
        lifecycle.append(item_lifecycle)

        if item_lifecycle.status == "expired":
            expired.append(artifact)
            status = "expired"
        elif item_lifecycle.status == "stale":
            stale.append(artifact)
            if status != "expired":
                status = "stale"

        if item_lifecycle.next_refresh_at and (
            next_refresh_at is None or item_lifecycle.next_refresh_at < next_refresh_at
        ):
            next_refresh_at = item_lifecycle.next_refresh_at

    return EvidenceSetSummary(
        status=status,
        lifecycle=lifecycle,
        stale_artifacts=stale,
        expired_artifacts=expired,
        next_refresh_at=next_refresh_at,
    )


def extract_evidence_artifacts(
    *,
    kind: EntityKind,
    entity_id: str,
    metadata: Mapping[str, object] | None,
    default_source: str = "metadata",
) -> Sequence[EvidenceArtifact]:
    if not metadata:
        return []

    artifacts: list[EvidenceArtifact] = []

    evidence = metadata.get("evidence")
    if isinstance(evidence, Mapping):
        artifacts.append(
            _to_artifact(
                kind=kind,
                entity_id=entity_id,
                source=default_source,
                payload=evidence,
            )
        )

    attachments = metadata.get("attachments") or metadata.get("evidenceArtifacts")
    if isinstance(attachments, Sequence):
        for attachment in attachments:
            if not isinstance(attachment, Mapping):
                continue
            source = attachment.get("source")
            source_label = source if isinstance(source, str) else "attachment"
            artifacts.append(
                _to_artifact(
                    kind=kind,
                    entity_id=entity_id,
                    source=source_label,
                    payload=attachment,
                )
            )

    return artifacts


def _dedupe_artifacts(artifacts: Sequence[EvidenceArtifact]) -> list[EvidenceArtifact]:
    seen: MutableMapping[str, EvidenceArtifact] = {}
    for artifact in artifacts:
        if artifact.artifact_id not in seen:
            seen[artifact.artifact_id] = artifact
    return list(seen.values())


def _to_artifact(
    *,
    kind: EntityKind,
    entity_id: str,
    source: str,
    payload: Mapping[str, object],
) -> EvidenceArtifact:
    collected_at = _coerce_datetime(
        payload.get("collectedAt")
        or payload.get("collected_at")
        or payload.get("createdAt")
        or payload.get("created_at")
    )
    expires_at = _coerce_datetime(
        payload.get("expiresAt")
        or payload.get("expires_at")
        or payload.get("validUntil")
        or payload.get("valid_until")
    )
    labels = _collect_labels(payload.get("labels") or payload.get("tags"))
    artifact_id = str(
        payload.get("id")
        or f"{kind}-{entity_id}-{source}-{collected_at.isoformat() if collected_at else 'unknown'}"
    )

    return EvidenceArtifact(
        artifact_id=artifact_id,
        entity_id=entity_id,
        source=source,
        collected_at=collected_at,
        expires_at=expires_at,
        content_type=str(payload.get("contentType")) if payload.get("contentType") else None,
        labels=labels,
        metadata=payload,
    )


def _collect_labels(values: object | None) -> list[str]:
    if isinstance(values, Sequence) and not isinstance(values, (str, bytes, bytearray)):
        return [str(value) for value in values if isinstance(value, (str, bytes))]
    if isinstance(values, Mapping):
        return [
            str(value) for value in values.values() if isinstance(value, (str, bytes))
        ]
    return []


def _coerce_datetime(value: object | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        dt = (
            datetime.utcfromtimestamp(float(value) / 1000)
            if value > 10**12
            else datetime.utcfromtimestamp(float(value))
        )
        return dt
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _compute_expiry(
    collected_at: datetime | None,
    hard_expiry_days: int | None,
    now: datetime,
) -> datetime | None:
    if hard_expiry_days is None:
        return None
    base = collected_at or now
    return base + timedelta(days=hard_expiry_days)


def _compute_age_days(collected_at: datetime | None, now: datetime) -> int | None:
    if not collected_at:
        return None
    if collected_at > now:
        return 0
    return int((now - collected_at).days)


def _compute_ttl_days(
    collected_at: datetime | None,
    expires_at: datetime | None,
    hard_expiry_days: int | None,
) -> int | None:
    if collected_at and expires_at:
        return int((expires_at - collected_at).days)
    return hard_expiry_days
