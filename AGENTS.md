# Cerebro Agent Instructions

## Core Commands

- Bootstrap linters: `make lint-bootstrap`
- Full PR validation: `make verify`
- Focused tests: `go test ./path/to/package -run 'TestName' -count=1 -v`

## Droid Creation Modes

- Fix review feedback by inspecting existing PR comments, reviews, and failing checks before editing.
- Add regression tests for every high-confidence bug or security finding that can regress.
- For new source integrations, follow existing `sources/` patterns for config parsing, validation, preview/runtime behavior, and tests.
- Keep changes scoped to the triggering issue or PR; do not merge PRs or push directly to the default branch.

## Repository Conventions

- Prefer repo `make` targets over ad-hoc commands.
- Go dependencies are vendored; avoid dependency changes unless explicitly requested.
- Do not hand-edit generated or contract-governed outputs without running the matching `Makefile` check/sync target.
- Public-facing config/example changes should run `python3 scripts/oss_audit.py` when that script is present.

## Finding Rule Design Notes

- Model findings as remediable control gaps or durable risk states, not as a one-to-one mirror of upstream alerts. Source-native alerts and threats should usually become evidence and graph context.
- SentinelOne threat records are evidence. Prefer endpoint-, configuration-, or control-change findings such as active endpoint infection, failed mitigation, stale/offline agents, detect-only protection, risky exclusions, and protection control tampering.
- Fingerprint SentinelOne endpoint posture findings by the affected agent/control, not by individual threat IDs, so repeated threats layer as evidence under one actionable finding.
- Map controls by finding type: incident response/containment for active infection or failed mitigation, endpoint coverage for stale/offline agents, and protection/change-management controls for detect-only mode or risky exclusions.
