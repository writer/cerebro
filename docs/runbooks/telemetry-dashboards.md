# Telemetry Dashboards Runbook

## Purpose
- Monitor `frontend_observation_events` signal quality and orientation trends.
- Ensure dashboards and analyst agents consume fresh, well-formed telemetry.

## Prerequisites
- PostgreSQL / warehouse connection configured via `DATABASE_URL`.
- Access to Cerebro application dashboards and GitHub Actions.
- Local environment with `uv` or `python3` for running scripts.

## Routine Daily Tasks
1. Review dashboard widgets sourced from `DashboardRepository.get_orientation_summary()` to confirm data updated within the last 24h.
2. Scan trend deltas for sudden spikes in `top_event_types` or `top_components`; capture anomalies in the telemetry notebook or incident tracker.
3. Check GitHub Actions → **Docstring quality** workflow for the latest status (ensures telemetry scripts stay linted / documented).

## Deep-Dive Triage
- Run orientation summary CLI for custom windows:
  ```bash
  uv run python scripts/generate_orientation_summary.py --window-hours 6 --baseline-hours 48
  ```
- Export raw trajectories when validating anomalies:
  ```bash
  uv run python scripts/export_agent_policy_dataset.py \
    --window-days 3 \
    --min-events 2 \
    --output tmp/trajectories.jsonl
  ```
- Assess data health via:
  ```bash
  uv run python scripts/analyze_frontend_events.py --window-days 7 --print-samples
  ```

## Alert Response
| Condition | Response |
|-----------|----------|
| Telemetry summary shows `missing_metadata` rising above 5% | Validate instrumented components in FE repo, re-run analyzer with `--print-samples`, open bug if specific component identified. |
| Orientation summary returns `total_events_current == 0` | Confirm benchmark nightly job completed, verify ingestion pipeline, escalate to platform if warehouse unreachable. |
| Scripts fail due to DB auth | Rotate credentials or confirm secrets in GitHub Actions; rerun job after fix. |

## Reporting & Follow-Up
- File anomalies in the telemetry operations board with CLI output attached.
- Update labels on RLHF datasets when exports trigger downstream training.
- If repeated data gaps occur, schedule pairing with frontend team for instrumentation review.
