#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from enum import Enum
import json
from pathlib import Path
import re
import sys
from typing import Any


REQUIRED_STAGES = (
    "source_origin",
    "evidencecas_write",
    "evidencecas_audit",
    "cerebro_source_ingest",
    "cerebro_projection",
    "siem_signal",
    "infra_observability",
)

REQUIRED_JOIN_FIELDS = (
    "tenant_id",
    "source_system",
    "source_runtime_id",
    "source_event_id",
    "case_id",
    "evidence_id",
    "resource_urn",
    "request_id",
)

CAS_IDENTITY_FIELDS = (
    "evidence_cas_uri",
    "evidence_cas_digest",
    "evidence_cas_merkle_root",
    "evidence_cas_commit_id",
    "evidence_cas_ref_type",
)

ASSERTIONS = (
    "VAL-CROSS-001",
    "VAL-CROSS-002",
    "VAL-CROSS-004",
    "VAL-CROSS-005",
    "VAL-CROSS-006",
    "VAL-CROSS-007",
    "VAL-CROSS-008",
    "VAL-CROSS-013",
    "VAL-CROSS-017",
    "VAL-CROSS-018",
)

SAFE_SOURCE_SYSTEM = "panopticon"
SENSITIVE_PATTERNS = (
    re.compile(r"arn:aws[a-zA-Z-]*:[^\s,;)\]}]+"),
    re.compile(r"\b\d{12}\b"),
    re.compile(r"https?://([A-Za-z0-9-]+\.)+[A-Za-z]{2,}(:\d+)?(/[^\s,;)\]}]*)?"),
    re.compile(r"(?i)(secret|token|private[_-]?key)[\"'=:\s]+[A-Za-z0-9_./:=@+-]+"),
)
CAS_DIGEST_RE = re.compile(r"^sha256:[A-Za-z0-9._-]{16,}$")
FIRST_VISIT_VISIBLE_STATUSES = {"linked", "setup_needed", "orphan", "missing_resource", "missing_case"}


class LifecycleState(str, Enum):
    SOURCE_OBSERVED = "source_observed"
    EVIDENCE_WRITTEN = "evidence_written"
    EVIDENCE_AUDITED = "evidence_audited"
    SOURCE_INGESTED = "source_ingested"
    PROJECTED = "projected"
    SIEM_SIGNALED = "siem_signaled"
    OBSERVABILITY_RECORDED = "observability_recorded"


STAGE_LIFECYCLE_STATES = {
    "source_origin": LifecycleState.SOURCE_OBSERVED,
    "evidencecas_write": LifecycleState.EVIDENCE_WRITTEN,
    "evidencecas_audit": LifecycleState.EVIDENCE_AUDITED,
    "cerebro_source_ingest": LifecycleState.SOURCE_INGESTED,
    "cerebro_projection": LifecycleState.PROJECTED,
    "siem_signal": LifecycleState.SIEM_SIGNALED,
    "infra_observability": LifecycleState.OBSERVABILITY_RECORDED,
}
LIFECYCLE_STATE_ORDER = {state.value: index for index, state in enumerate(STAGE_LIFECYCLE_STATES.values())}


class LifecycleProbeError(ValueError):
    """Raised when a synthetic lifecycle transcript violates the cross-system contract."""


def _parse_time(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleProbeError(f"{context} must contain a non-empty RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LifecycleProbeError(f"{context} has invalid timestamp {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _scan_sensitive_values(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _scan_sensitive_values(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _scan_sensitive_values(child, f"{path}[{index}]")
        return
    if not isinstance(value, str):
        value = str(value)
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(value):
            raise LifecycleProbeError(f"{path} contains sensitive or broad-surface unsafe value")


def _stage_map(run: dict[str, Any], run_index: int) -> dict[str, dict[str, Any]]:
    stages = run.get("stages")
    if not isinstance(stages, list):
        raise LifecycleProbeError(f"runs[{run_index}].stages must be a list")
    by_stage: dict[str, dict[str, Any]] = {}
    for stage in stages:
        if not isinstance(stage, dict):
            raise LifecycleProbeError(f"runs[{run_index}].stages contains a non-object stage")
        name = str(stage.get("stage") or "").strip()
        if not name:
            raise LifecycleProbeError(f"runs[{run_index}].stages contains a stage without stage name")
        if name in by_stage:
            raise LifecycleProbeError(f"runs[{run_index}] has duplicate stage {name!r}")
        by_stage[name] = stage
    for required in REQUIRED_STAGES:
        if required not in by_stage:
            raise LifecycleProbeError(f"runs[{run_index}] is missing required stage {required}")
    return by_stage


def _require_join_fields(run: dict[str, Any], stages: dict[str, dict[str, Any]], run_index: int) -> None:
    expected: dict[str, str] = {}
    for stage_name, stage in stages.items():
        exempt_source_origin_cas = stage_name == "source_origin"
        for field in REQUIRED_JOIN_FIELDS:
            value = str(stage.get(field) or "").strip()
            if not value:
                raise LifecycleProbeError(f"runs[{run_index}].{stage_name} is missing required field {field}")
            previous = expected.setdefault(field, value)
            if previous != value:
                raise LifecycleProbeError(f"runs[{run_index}].{stage_name}.{field} differs from lifecycle value")
        if not exempt_source_origin_cas and not str(stage.get("evidence_cas_uri") or "").strip():
            raise LifecycleProbeError(f"runs[{run_index}].{stage_name} is missing required field evidence_cas_uri")
        if stage_name != "source_origin" and not (stage.get("trace_id") or stage.get("traceparent")):
            raise LifecycleProbeError(f"runs[{run_index}].{stage_name} is missing trace_id or traceparent")

    source_origin = stages["source_origin"]
    if not (source_origin.get("trace_id") or source_origin.get("traceparent")):
        raise LifecycleProbeError(f"runs[{run_index}].source_origin is missing trace_id or traceparent")
    if str(run.get("source_event_id") or "") and str(run["source_event_id"]) != expected["source_event_id"]:
        raise LifecycleProbeError(f"runs[{run_index}].source_event_id does not match stage source_event_id")


def _require_integrity_consistency(stages: dict[str, dict[str, Any]], run_index: int) -> tuple[str, ...]:
    expected: dict[str, str] = {}
    for stage_name, stage in stages.items():
        if stage_name == "source_origin":
            continue
        for field in CAS_IDENTITY_FIELDS:
            value = str(stage.get(field) or "").strip()
            if not value:
                raise LifecycleProbeError(f"runs[{run_index}].{stage_name} is missing required field {field}")
            previous = expected.setdefault(field, value)
            if previous != value:
                raise LifecycleProbeError(
                    f"runs[{run_index}].{stage_name}.{field} does not match EvidenceCAS identity"
                )
            if field == "evidence_cas_uri" and not value.startswith("evidencecas://"):
                raise LifecycleProbeError(f"runs[{run_index}].{stage_name}.{field} must use evidencecas:// URI")
            if field in {"evidence_cas_digest", "evidence_cas_merkle_root"} and not CAS_DIGEST_RE.match(value):
                raise LifecycleProbeError(f"runs[{run_index}].{stage_name}.{field} must use sha256 integrity identity")
    return tuple(expected[field] for field in CAS_IDENTITY_FIELDS)


def _require_timeline(stages: dict[str, dict[str, Any]], run_index: int) -> None:
    last_observed: datetime | None = None
    source_occurred: datetime | None = None
    for stage_name in REQUIRED_STAGES:
        stage = stages[stage_name]
        occurred = _parse_time(stage.get("occurred_at"), f"runs[{run_index}].{stage_name}.occurred_at")
        observed = _parse_time(stage.get("observed_at"), f"runs[{run_index}].{stage_name}.observed_at")
        if observed < occurred:
            raise LifecycleProbeError(f"runs[{run_index}].{stage_name}.observed_at is before occurred_at")
        if last_observed and observed < last_observed:
            raise LifecycleProbeError(f"runs[{run_index}].{stage_name}.observed_at is out of lifecycle order")
        if source_occurred is None:
            source_occurred = occurred
        elif occurred != source_occurred:
            raise LifecycleProbeError(f"runs[{run_index}].{stage_name}.occurred_at does not preserve source time")
        last_observed = observed


def _require_lifecycle_states(stages: dict[str, dict[str, Any]], run_index: int) -> None:
    last_order = -1
    for stage_name in REQUIRED_STAGES:
        stage = stages[stage_name]
        state = str(stage.get("lifecycle_state") or "").strip()
        expected = STAGE_LIFECYCLE_STATES[stage_name].value
        if not state:
            raise LifecycleProbeError(f"runs[{run_index}].{stage_name} is missing lifecycle_state")
        if state not in LIFECYCLE_STATE_ORDER:
            raise LifecycleProbeError(f"runs[{run_index}].{stage_name} lifecycle_state {state!r} is unsupported")
        if state != expected:
            raise LifecycleProbeError(f"runs[{run_index}].{stage_name} lifecycle_state must be {expected!r}")
        order = LIFECYCLE_STATE_ORDER[state]
        if order < last_order:
            raise LifecycleProbeError(f"runs[{run_index}].{stage_name} lifecycle_state moves backward")
        last_order = order


def _require_reconstruction(stages: dict[str, dict[str, Any]], run_index: int) -> None:
    for key in ("resource_urn", "case_id", "evidence_id"):
        index: dict[str, set[str]] = defaultdict(set)
        for stage_name, stage in stages.items():
            index[str(stage[key])].add(stage_name)
        if len(index) != 1:
            raise LifecycleProbeError(f"runs[{run_index}] cannot reconstruct lifecycle from {key}")
        observed_stages = next(iter(index.values()))
        missing = set(REQUIRED_STAGES).difference(observed_stages)
        if missing:
            raise LifecycleProbeError(f"runs[{run_index}] reconstruction by {key} misses {sorted(missing)}")


def _require_first_visit_visibility(stages: dict[str, dict[str, Any]], run_index: int) -> str:
    projection = stages["cerebro_projection"]
    infra = stages["infra_observability"]
    siem = stages["siem_signal"]
    status = str(projection.get("first_visit_status") or projection.get("link_status") or "").strip()
    if not status:
        raise LifecycleProbeError(f"runs[{run_index}].cerebro_projection is missing first_visit_status")
    if status not in FIRST_VISIT_VISIBLE_STATUSES:
        raise LifecycleProbeError(f"runs[{run_index}].cerebro_projection first_visit_status {status!r} is unsupported")
    if status != "linked":
        for stage_name, stage in (("infra_observability", infra), ("siem_signal", siem)):
            visible = str(stage.get("first_visit_status") or stage.get("link_status") or "").strip()
            if visible != status:
                raise LifecycleProbeError(f"runs[{run_index}].{stage_name} does not expose first-visit {status} state")
    return status


def _require_idempotency(runs: list[dict[str, Any]], fingerprints: list[tuple[str, str, tuple[str, ...]]]) -> tuple[int, int]:
    first_seen: dict[tuple[str, str], tuple[int, tuple[str, ...]]] = {}
    duplicate_count = 0
    lifecycle_keys: set[tuple[str, str]] = set()
    for index, (source_event_id, evidence_id, cas_identity) in enumerate(fingerprints):
        key = (source_event_id, evidence_id)
        lifecycle_keys.add(key)
        run = runs[index]
        if key not in first_seen:
            first_seen[key] = (index, cas_identity)
            continue
        duplicate_count += 1
        first_index, original_identity = first_seen[key]
        if cas_identity != original_identity:
            raise LifecycleProbeError(f"runs[{index}] conflicts with idempotent lifecycle from runs[{first_index}]")
        if not bool(run.get("idempotent_replay")) and not str(run.get("duplicate_of") or "").strip():
            raise LifecycleProbeError(f"runs[{index}] repeats source_event_id/evidence_id without idempotent marker")
    return duplicate_count, len(lifecycle_keys)


def _validate_legacy_records(transcript: dict[str, Any]) -> int:
    records = transcript.get("legacy_records") or []
    if not isinstance(records, list):
        raise LifecycleProbeError("legacy_records must be a list when present")
    compatible = 0
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise LifecycleProbeError(f"legacy_records[{index}] must be an object")
        for field in ("tenant_id", "source_system", "source_runtime_id", "source_event_id", "evidence_id", "resource_urn", "evidence_cas_uri"):
            if not str(record.get(field) or "").strip():
                raise LifecycleProbeError(f"legacy_records[{index}] is missing required field {field}")
        trace_absent = not (record.get("trace_id") or record.get("traceparent"))
        request_absent = not record.get("request_id")
        if (trace_absent or request_absent) and not record.get("observability_gap"):
            raise LifecycleProbeError(f"legacy_records[{index}] needs observability_gap for optional request/trace absence")
        status = str(record.get("compatibility_status") or "")
        if status != "legacy_compatible":
            raise LifecycleProbeError(f"legacy_records[{index}] compatibility_status must be legacy_compatible")
        compatible += 1
    return compatible


def validate_transcript(transcript: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(transcript, dict):
        raise LifecycleProbeError("transcript must be a JSON object")
    _scan_sensitive_values(transcript)
    runs = transcript.get("runs")
    if not isinstance(runs, list) or not runs:
        raise LifecycleProbeError("transcript must contain at least one run")

    fingerprints: list[tuple[str, str, tuple[str, ...]]] = []
    first_visit_statuses: list[str] = []
    orphan_or_setup_visible = 0
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise LifecycleProbeError(f"runs[{run_index}] must be an object")
        stages = _stage_map(run, run_index)
        _require_join_fields(run, stages, run_index)
        cas_identity = _require_integrity_consistency(stages, run_index)
        _require_timeline(stages, run_index)
        _require_lifecycle_states(stages, run_index)
        _require_reconstruction(stages, run_index)
        first_visit_status = _require_first_visit_visibility(stages, run_index)
        first_visit_statuses.append(first_visit_status)
        if first_visit_status != "linked":
            orphan_or_setup_visible += 1
        fingerprints.append((str(stages["source_origin"]["source_event_id"]), str(stages["source_origin"]["evidence_id"]), cas_identity))

    idempotent_replays, distinct_lifecycle_keys = _require_idempotency(runs, fingerprints)
    legacy_compatible_records = _validate_legacy_records(transcript)
    return {
        "status": "pass",
        "runs": len(runs),
        "distinct_lifecycle_keys": distinct_lifecycle_keys,
        "idempotent_replays": idempotent_replays,
        "first_visit_statuses": sorted(set(first_visit_statuses)),
        "orphan_or_setup_visible": orphan_or_setup_visible,
        "legacy_compatible_records": legacy_compatible_records,
        "assertions": list(ASSERTIONS),
    }


def _synthetic_stage(
    stage: str,
    *,
    observed_at: datetime,
    run_id: str,
    source_event_id: str,
    evidence_id: str,
    first_visit_status: str,
) -> dict[str, Any]:
    occurred_at = datetime(2026, 6, 9, 12, 0, 0, tzinfo=UTC)
    common = {
        "stage": stage,
        "tenant_id": "synthetic-tenant-lifecycle",
        "source_system": SAFE_SOURCE_SYSTEM,
        "source_runtime_id": "synthetic-panopticon-runtime",
        "source_event_id": source_event_id,
        "case_id": "synthetic-case-lifecycle",
        "evidence_id": evidence_id,
        "resource_urn": "urn:writer:synthetic:resource:lifecycle",
        "request_id": f"synthetic-request-{run_id}",
        "trace_id": f"synthetic-trace-{run_id}",
        "traceparent": f"00-{_hexish(run_id, 32)}-{_hexish(run_id, 16)}-01",
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "evidence_cas_uri": f"evidencecas://synthetic/lifecycle/{evidence_id}",
        "evidence_cas_digest": f"sha256:syntheticdigest{_hexish(run_id, 16)}",
        "evidence_cas_merkle_root": f"sha256:syntheticmerkle{_hexish(run_id, 16)}",
        "evidence_cas_commit_id": f"synthetic-commit-{run_id}",
        "evidence_cas_ref_type": "iris.panopticon.synthetic.v1",
        "event_source": "synthetic_probe",
        "lifecycle_state": STAGE_LIFECYCLE_STATES[stage].value,
    }
    if stage == "source_origin":
        common["registration_status"] = "pending_evidencecas_registration"
        common.pop("evidence_cas_uri")
        common.pop("evidence_cas_digest")
        common.pop("evidence_cas_merkle_root")
        common.pop("evidence_cas_commit_id")
        common.pop("evidence_cas_ref_type")
    if stage in {"cerebro_projection", "siem_signal", "infra_observability"}:
        common["first_visit_status"] = first_visit_status
        common["link_status"] = first_visit_status
    if stage == "siem_signal":
        common["alert_title"] = "Synthetic evidence lifecycle joinability probe"
        common["query_window"] = "bounded_15_minutes"
    if stage == "infra_observability":
        common["metric_status"] = "success" if first_visit_status == "linked" else first_visit_status
        common["dashboard_signal"] = "source-runtime-observability"
    return common


def _hexish(value: str, length: int) -> str:
    encoded = "".join(f"{ord(char):02x}" for char in value)
    padded = (encoded * ((length // max(len(encoded), 1)) + 1))[:length]
    return padded.ljust(length, "0")


def emit_synthetic_transcript(
    *,
    run_ids: list[str],
    first_visit_status: str = "linked",
    include_legacy: bool = False,
) -> dict[str, Any]:
    if first_visit_status not in FIRST_VISIT_VISIBLE_STATUSES:
        raise ValueError(f"unsupported first_visit_status {first_visit_status!r}")
    base = datetime(2026, 6, 9, 12, 0, 10, tzinfo=UTC)
    first_event_by_run: dict[str, tuple[str, str]] = {}
    runs = []
    for ordinal, run_id in enumerate(run_ids):
        if run_id in first_event_by_run:
            source_event_id, evidence_id = first_event_by_run[run_id]
            idempotent_replay = True
        else:
            source_event_id = f"synthetic-source-event-{run_id}"
            evidence_id = f"synthetic-evidence-{run_id}"
            first_event_by_run[run_id] = (source_event_id, evidence_id)
            idempotent_replay = False
        stages = [
            _synthetic_stage(
                stage,
                observed_at=base + timedelta(minutes=ordinal, seconds=offset),
                run_id=run_id,
                source_event_id=source_event_id,
                evidence_id=evidence_id,
                first_visit_status=first_visit_status,
            )
            for offset, stage in enumerate(REQUIRED_STAGES)
        ]
        run = {
            "run_id": f"synthetic-lifecycle-{ordinal + 1}",
            "source_event_id": source_event_id,
            "evidence_id": evidence_id,
            "idempotency_key": f"synthetic-idempotency-{source_event_id}",
            "stages": stages,
        }
        if idempotent_replay:
            run["idempotent_replay"] = True
            run["duplicate_of"] = source_event_id
        runs.append(run)

    transcript: dict[str, Any] = {
        "schema_version": "synthetic-lifecycle-probe.v1",
        "description": "Synthetic safe cross-system lifecycle transcript for EvidenceCAS, Cerebro, infra, and SIEM joinability validation.",
        "runs": runs,
    }
    if include_legacy:
        transcript["legacy_records"] = [
            {
                "tenant_id": "synthetic-tenant-lifecycle",
                "source_system": SAFE_SOURCE_SYSTEM,
                "source_runtime_id": "legacy-panopticon-runtime",
                "source_event_id": "legacy-source-event-with-required-keys",
                "evidence_id": "legacy-evidence-with-required-keys",
                "resource_urn": "urn:writer:synthetic:resource:legacy",
                "evidence_cas_uri": "evidencecas://synthetic/legacy/evidence",
                "evidence_cas_digest": "sha256:syntheticlegacydigest",
                "request_id": "legacy-request-compatible",
                "trace_id": "legacy-trace-compatible",
                "compatibility_status": "legacy_compatible",
            }
        ]
    return transcript


def _print_report(report: dict[str, Any]) -> None:
    print(f"status\t{report['status']}")
    print(f"runs\t{report['runs']}")
    print(f"distinct_lifecycle_keys\t{report['distinct_lifecycle_keys']}")
    print(f"idempotent_replays\t{report['idempotent_replays']}")
    print(f"legacy_compatible_records\t{report['legacy_compatible_records']}")
    for status in report["first_visit_statuses"]:
        print(f"first_visit_status\t{status}")
    for assertion in report["assertions"]:
        print(f"assertion\t{assertion}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate synthetic cross-system evidence lifecycle transcripts without exposing sensitive values."
    )
    parser.add_argument("--transcript", type=Path, help="JSON transcript to validate.")
    parser.add_argument("--emit-fixture", action="store_true", help="Emit a synthetic safe fixture instead of validating.")
    parser.add_argument("--run-id", action="append", default=[], help="Synthetic run ID to include when emitting a fixture.")
    parser.add_argument(
        "--first-visit-status",
        default="linked",
        choices=sorted(FIRST_VISIT_VISIBLE_STATUSES),
        help="First-visit status for emitted fixture runs.",
    )
    parser.add_argument("--include-legacy", action="store_true", help="Include a legacy-compatible record in emitted fixtures.")
    args = parser.parse_args(argv)

    if args.emit_fixture:
        run_ids = args.run_id or ["synthetic-run-alpha", "synthetic-run-alpha", "synthetic-run-beta"]
        print(json.dumps(emit_synthetic_transcript(run_ids=run_ids, first_visit_status=args.first_visit_status, include_legacy=args.include_legacy), indent=2, sort_keys=True))
        return 0
    if not args.transcript:
        parser.error("--transcript is required unless --emit-fixture is set")
    with args.transcript.open("r", encoding="utf-8") as handle:
        transcript = json.load(handle)
    report = validate_transcript(transcript)
    _print_report(report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LifecycleProbeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
