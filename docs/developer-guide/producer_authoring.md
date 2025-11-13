# Producer Authoring Guide

## Prerequisites

- Install the project toolchain (`uv`, Python 3.9/3.11, Node) and bootstrap the repo with `uv sync --extra dev`.
- Familiarize yourself with the producer architecture in `src/cerebro/findings/producers` and the shared utilities under `src/cerebro/findings/producers/utils`.
- Ensure you can run the focused test suites locally (`uv run pytest tests/findings`).

## Implementation Workflow

1. **Select the right base module**: place AWS, Azure, GCP, Kubernetes, GitHub, and telemetry producers inside their provider namespace to benefit from existing helpers (e.g., `BaseAWSProducer`).
2. **Normalize context early**: call `ProducerRunContext.ensure(context)` at the start of `evaluate` to access shared metadata (namespace posture, rule overrides, etc.).
3. **Resolve rule IDs deterministically**: use `resolve_rule_id(rule_name=..., context=run_context)`; avoid hard-coding UUIDs so rule synchronization stays consistent.
4. **Build evidence with typed helpers**: prefer `build_*` utilities from `cerebro.findings.producers.utils.evidence` (e.g., `build_storage_secret_evidence`, `build_runner_host_exposure`). They enforce clipping and schema consistency.
5. **Reuse severity helpers**: leverage functions in `utils.severity` (`exposures_contain_public`, `downgrade_severity_for_namespace_policy`) rather than re-implementing bespoke checks.
6. **Return early on empty findings**: collect all candidate exposures, bail out when the list is empty, then call `self.create_finding(...)` once per resource.

## Evidence & Telemetry Expectations

- `BaseFindingProducer.create_finding` now records Prometheus metrics (`cerebro_finding_evidence_bytes`, `cerebro_finding_evidence_fields`) and emits a debug log containing the producer name, severity, byte size, and top-level key count.
- Keep evidence payloads minimal: rely on clipping helpers (`clip_sequence`, `compact_mapping`) and avoid embedding raw provider responses.
- Serialization failures are tracked via `cerebro_finding_evidence_serialization_failures_total`; if you see increments, sanitize custom objects before passing them into evidence.

## Testing Checklist

- **Unit coverage**: add targeted tests under `tests/findings/` mirroring existing suites. When possible, create fixture-driven regression tests (see `tests/findings/test_producer_regression_snapshots.py`).
- **Regression snapshots**: store input/expected payloads in `tests/findings/fixtures/` and assert on summaries, severity, and evidence structures for deterministic validation.
- **Command suite**:
  ```bash
  uv run ruff check src/cerebro/findings/producers/<provider>/<module>.py
  uv run mypy src/cerebro/findings/producers src/cerebro/metrics
  uv run pytest tests/findings
  ```
- Include any new fixtures or tests in commits; fixtures should be anonymized and free of customer data.

## CI & Operational Guardrails

- Pre-commit enforces Ruff on modified producer directories—run the lint command locally to avoid rewrites.
- Producer convention tests (`tests/findings/test_producer_conventions.py`) ensure typed contexts, evidence builders, and `clip_sequence` usage; keep them green.
- The producer audit script (`scripts/producer_audit.py`) runs in CI. Execute `uv run python scripts/producer_audit.py --summary` after large refactors to surface missing builders or context normalizations.
- Observability dashboards consume the new evidence metrics; each producer should aim for <32 top-level keys and <64 KiB serialized evidence unless there is a strong justification.
