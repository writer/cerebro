# Benchmark Regression Runbook

## Scope
Operational steps for responding to benchmark regressions detected by CI workflows or agent-facing tooling.

## Signals & Tooling
- GitHub Actions workflows:
  - `benchmarks.yml` (merge gating)
  - `benchmarks-nightly.yml` (03:30 UTC drift watch)
- Agent tool: `benchmarks_status`
- Artifact: `benchmarks/results/scorecard.json`

## Immediate Checks
1. Inspect the failing workflow logs for the regression summary step.
2. Download the scorecard artifact and open locally:
   ```bash
   gh run download <run-id> --name benchmark-scorecard --dir tmp/benchmarks
   jq '.' tmp/benchmarks/scorecard.json
   ```
3. Query the agent tool for a high-level synopsis (optional):
   ```bash
   uv run cerebro agents invoke benchmarks_status --include-details
   ```

## Triage Flow
| Question | Action |
|----------|--------|
| Did a specific scenario flip from pass → fail? | Review scenario logs in `benchmarks/logs/<scenario>.log`, bisect recent code touching related components. |
| Are multiple scenarios failing with similar symptoms? | Look for shared dependencies (e.g., KMS providers, session factories) and validate configuration defaults. |
| Do failures reproduce locally? | Run `uv run make benchmarks` or the individual scenario shell script inside the container image. |

## Remediation Steps
1. Capture regression details in the engineering tracker with links to the failing run and scorecard diff.
2. If configuration-related, patch `.github/workflows/benchmarks*.yml` and re-run the workflow using `gh workflow run`.
3. For product bugs, open a hotfix or revert commit; ensure the agent-facing `benchmarks_status` tool reflects the cleared state after rerun.
4. Confirm nightly workflow on the next cycle or manually dispatch after fixes to re-establish baseline.

## Escalation
- **P1**: Benchmarks blocked on `main` for >4h or regression impacts release gating — page the on-call platform engineer.
- **P2**: Nightly drift detection fails two consecutive runs — create an incident ticket and alert the autonomy lead.

## Postmortem Notes
- Archive the scorecard JSON and remediation summary in the benchmarks knowledge base.
- Update the scenario annotations with additional hints if manual triage was required.
