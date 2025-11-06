from __future__ import annotations

from datetime import datetime, timedelta

from cerebro_sdk.security_center import (
    EvidenceArtifact,
    LifecyclePolicy,
    evaluate_evidence_lifecycle,
    summarize_evidence_set,
    extract_evidence_artifacts,
)


def test_evaluate_evidence_lifecycle_flags_stale_artifacts() -> None:
    artifact = EvidenceArtifact(
        artifact_id="artifact-1",
        entity_id="vendor-1",
        source="metadata",
        collected_at=datetime(2024, 9, 1),
        expires_at=datetime(2024, 10, 1),
        metadata={},
    )

    lifecycle = evaluate_evidence_lifecycle(
        artifact,
        LifecyclePolicy(max_age_days=20, refresh_window_days=10),
        now=datetime(2024, 9, 25),
    )

    assert lifecycle.status == "stale"
    assert lifecycle.requires_action is True


def test_summarize_evidence_set_dedupes_by_identifier() -> None:
    now = datetime.utcnow()
    artifacts = [
        EvidenceArtifact(
            artifact_id="artifact-1",
            entity_id="vendor-1",
            source="metadata",
            collected_at=now - timedelta(days=40),
            expires_at=now - timedelta(days=5),
            metadata={},
        ),
        EvidenceArtifact(
            artifact_id="artifact-1",
            entity_id="vendor-1",
            source="metadata",
            collected_at=now - timedelta(days=40),
            expires_at=now - timedelta(days=5),
            metadata={},
        ),
    ]

    summary = summarize_evidence_set(artifacts, LifecyclePolicy(max_age_days=30), now=now)
    assert summary.status == "expired"
    assert len(summary.expired_artifacts) == 1
    assert len(summary.lifecycle) == 1


def test_extract_evidence_artifacts_reads_attachments() -> None:
    artifacts = extract_evidence_artifacts(
        kind="vendor",
        entity_id="vendor-1",
        metadata={
            "evidence": {
                "id": "primary",
                "collected_at": "2024-09-01T00:00:00Z",
                "expires_at": "2024-12-01T00:00:00Z",
                "tags": {"control": "cc-2.1"},
            },
            "attachments": [
                {
                    "id": "attachment-1",
                    "source": "pentest",
                    "collectedAt": "2024-08-01T00:00:00Z",
                    "expiresAt": "2025-08-01T00:00:00Z",
                    "labels": ["pentest"],
                }
            ],
        },
    )

    assert len(artifacts) == 2
    assert artifacts[0].artifact_id == "primary"
    assert artifacts[1].source == "pentest"
