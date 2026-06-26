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
- Go dependencies are module-managed; avoid dependency changes unless explicitly requested and validate them through the relevant `make` targets.
- Do not hand-edit generated or contract-governed outputs without running `make contracts-check` or the matching focused `Makefile` check/sync target.
- Public-facing config/example changes should run `make oss-audit`; generated docs changes should also run `make docs-drift-check`.

## Public PR Data Safety

- Treat public PR titles, descriptions, comments, commit messages, and check summaries as public internet content.
- Do not include tenant names, environment names, hostnames, account IDs, graph counts, candidate counts, rule-hit counts, finding examples, resource labels, URNs, operational endpoints, deployment details, or closeout/backfill details in public PR metadata.
- Keep public PR descriptions high-level: summarize the code intent, tests run, and any non-sensitive compatibility notes only.
- Put sensitive analysis, rollout notes, validation counts, environment-specific observations, and closeout plans in internal channels or local notes, not in public repository metadata.
- Before creating or editing a public PR, re-read the body and remove any concrete customer, infrastructure, security-finding, or environment data.

## Scope Discipline

- [`docs/engineering/non-goals.md`](docs/engineering/non-goals.md) is the canonical list of things Cerebro intentionally does not do. Read it before proposing changes that touch storage shape, the Source CDK budget, the Cypher safety validator, the findings platform contract, the action engine, runtime response, or the platform/security namespace boundary.
- A change that crosses any non-goal must cite the relevant entry in the PR description, state which "What would change this" criterion has been met, and update `docs/engineering/non-goals.md` in the same change.
- When in doubt, prefer the narrower interpretation. Scope creep that quietly bypasses a non-goal is a review-blocker, not a discussion.

## Persona View Lens Design

- Read [`docs/domains/persona-view-lenses.md`](docs/domains/persona-view-lenses.md) before changing persona behavior, navigation contracts, GRC/security homepage semantics, or docs that describe the product split.
- Personas are enrichment layers over shared graph facts. They should not create separate truth, duplicate backend contracts, or imply authorization differences unless the change explicitly ships a permissions model.
- A useful persona lens defines the audience's first question, promoted signals, decision frame, work queue, next actions, and question starters. Do not stop at renaming the same dashboard.
- Lead with work and outcomes before navigation. Prefer "what is risky, what changed, who owns it, what should be fixed, and what can Cerebro explain?" over internal product taxonomy such as lens names, view names, graph jargon, or packaging language.
- Preserve distinct operating frames for common personas: Security prioritizes active risk, owners, affected assets, and remediation; Audit prioritizes controls, evidence freshness, scope gaps, and packs; Platform prioritizes source trust, runtime freshness, graph coverage, and inventory ownership; Leadership prioritizes material risk, readiness/trends, owner follow-up, and review-ready summaries.
- When modeling the same fact for multiple audiences, describe the persona-specific meaning. For example, a missing owner can mean remediation stall risk for Security, indefensible evidence for Audit, inventory cleanup for Platform, and an unresolved review follow-up for Leadership.

## Finding Rule Design Notes

- Cerebro should turn source/runtime evidence into a security knowledge graph plus durable, prioritized findings that explain the risky condition, affected asset/identity/control, why it matters, and the evidence or graph path supporting it.
- Valuable findings are current, graph-anchored, actionable, and risk-composed. Good examples include public exposure reaching a privileged principal, active endpoint infection, missing GRC ownership for a privileged identity, secret exposure tied to a repo or identity, and identity drift connected to offboarding or control failure.
- Non-valuable findings are raw temporal events promoted directly into findings without durable risk semantics. Avoid noisy findings for isolated token creation, policy edits, collaborator additions, old backfill records, or high-volume historical audit events unless they correlate into a current risky state with a clear remediation path.
- Findings should not remain open merely because an event happened once. Prefer current-state checks, graph correlation, stale-finding resolution, suppression, or evidence-only projection when the condition is no longer active or not independently actionable.
- Model findings as remediable control gaps or durable risk states, not as a one-to-one mirror of upstream alerts. Source-native alerts and threats should usually become evidence and graph context.
- Every durable rule needs an explicit `Lifecycle`, stable `FingerprintFields`, required attributes, control refs, false-positive guidance, and a runbook. A rule without lifecycle semantics is incomplete even if its matcher emits a plausible record.
- Choose the anchor before writing the matcher. Source-state rules anchor on durable provider IDs turned into tenant-scoped URNs; graph-anchored rules anchor on graph entities or paths. Never fingerprint on event IDs, timestamps, run IDs, pagination IDs, or vendor alert IDs unless that vendor object is itself the durable remediable state.
- Canonicalize or encode provider-controlled identifiers before placing them in URNs, event IDs, graph anchors, or finding fingerprints. Do not let `:`, `/`, display names, namespace prefixes, or lossy replace-all normalization create collisions between distinct provider objects.
- Preserve raw provider IDs, names, labels, and refs as attributes for investigation, but build graph and finding identity from stable tenant-scoped keys. If a source, projector, and rule all reference the same object, they should agree on one canonical URN form.
- For source-state rules, `OpenAnchor` and `CloseOnEvent` must meet in the middle: a close event must produce the same anchor stored on the open finding. If a remediating event has less detail than the opening event, add a rule-specific close path or do not claim closeout support.
- Deprovisioned, deleted, offboarded, inactive, or unmanaged resource snapshots should usually close posture findings for that resource. Removed resources should not leave stale open findings unless the finding is explicitly about unsafe removal.
- Missing, unknown, or hidden upstream data is not the same as a failing control. Treat unknown as unknown, preserve visibility in attributes when useful, and open findings only on positive evidence of the risky state.
- Event occurrence time should describe when the state was observed, not a future deadline or enforcement date. Keep future deadlines as attributes/evidence, but do not let them drive `OccurredAt` or stale-close ordering.
- Finding records should carry enough normalized context for graph projection and action safety: tenant-derived resource URNs, `primary_resource_urn`, source runtime ID, event ID, labels, owner/principal identifiers, and the raw provider IDs needed to re-derive the anchor.
- When a finding can trigger an action, the action target must be derived from or validated against the authorized finding or graph object. An explicit `target` field is a selector, not an authorization boundary.
- Action targets must come from verified identifiers such as provider user IDs, emails, identity URNs, or graph object URNs. Do not authorize or dispatch actions from display labels, owner names, summaries, or other human-readable context strings.
- Tests for new or changed rules should cover: positive open, negative non-open, required attributes, stable fingerprint/reopen behavior, remediation close, deprovision/offboard close where applicable, and a counterexample proving unrelated or contextless events do not close the finding.
- Source changes that feed findings must expose the exact attributes the rule uses, with tests for label-quality fields and edge cases such as fallback IDs, absent optional fields, and future/deadline timestamps.
- SentinelOne threat records are evidence. Prefer endpoint-, configuration-, or control-change findings such as active endpoint infection, failed mitigation, stale/offline agents, detect-only protection, risky exclusions, and protection control tampering.
- Fingerprint SentinelOne endpoint posture findings by the affected agent/control, not by individual threat IDs, so repeated threats layer as evidence under one actionable finding.
- Map controls by finding type: incident response/containment for active infection or failed mitigation, endpoint coverage for stale/offline agents, and protection/change-management controls for detect-only mode or risky exclusions.
