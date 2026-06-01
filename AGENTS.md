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

## Public PR Data Safety

- Treat public PR titles, descriptions, comments, commit messages, and check summaries as public internet content.
- Do not include tenant names, environment names, hostnames, account IDs, graph counts, candidate counts, rule-hit counts, finding examples, resource labels, URNs, operational endpoints, deployment details, or closeout/backfill details in public PR metadata.
- Keep public PR descriptions high-level: summarize the code intent, tests run, and any non-sensitive compatibility notes only.
- Put sensitive analysis, rollout notes, validation counts, environment-specific observations, and closeout plans in internal channels or local notes, not in public repository metadata.
- Before creating or editing a public PR, re-read the body and remove any concrete customer, infrastructure, security-finding, or environment data.

## Scope Discipline

- [`docs/NON_GOALS.md`](docs/NON_GOALS.md) is the canonical list of things Cerebro intentionally does not do. Read it before proposing changes that touch storage shape, the Source CDK budget, the Cypher safety validator, the findings platform contract, the action engine, runtime response, or the platform/security namespace boundary.
- A change that crosses any non-goal must cite the relevant entry in the PR description, state which "What would change this" criterion has been met, and update `docs/NON_GOALS.md` in the same change.
- When in doubt, prefer the narrower interpretation. Scope creep that quietly bypasses a non-goal is a review-blocker, not a discussion.

## Finding Rule Design Notes

- Cerebro should turn source/runtime evidence into a security knowledge graph plus durable, prioritized findings that explain the risky condition, affected asset/identity/control, why it matters, and the evidence or graph path supporting it.
- Valuable findings are current, graph-anchored, actionable, and risk-composed. Good examples include public exposure reaching a privileged principal, active endpoint infection, missing GRC ownership for a privileged identity, secret exposure tied to a repo or identity, and identity drift connected to offboarding or control failure.
- Non-valuable findings are raw temporal events promoted directly into findings without durable risk semantics. Avoid noisy findings for isolated token creation, policy edits, collaborator additions, old backfill records, or high-volume historical audit events unless they correlate into a current risky state with a clear remediation path.
- Findings should not remain open merely because an event happened once. Prefer current-state checks, graph correlation, stale-finding resolution, suppression, or evidence-only projection when the condition is no longer active or not independently actionable.
- Model findings as remediable control gaps or durable risk states, not as a one-to-one mirror of upstream alerts. Source-native alerts and threats should usually become evidence and graph context.
- SentinelOne threat records are evidence. Prefer endpoint-, configuration-, or control-change findings such as active endpoint infection, failed mitigation, stale/offline agents, detect-only protection, risky exclusions, and protection control tampering.
- Fingerprint SentinelOne endpoint posture findings by the affected agent/control, not by individual threat IDs, so repeated threats layer as evidence under one actionable finding.
- Map controls by finding type: incident response/containment for active infection or failed mitigation, endpoint coverage for stale/offline agents, and protection/change-management controls for detect-only mode or risky exclusions.
