# Cerebro Agent Instructions

## Finding Quality Guidance

- Cerebro should turn source/runtime evidence into a security knowledge graph plus durable, prioritized findings that explain the risky condition, affected asset/identity/control, why it matters, and the evidence or graph path supporting it.
- Valuable findings are current, graph-anchored, actionable, and risk-composed. Good examples include public exposure reaching a privileged principal, active endpoint infection, missing GRC ownership for a privileged identity, secret exposure tied to a repo or identity, and identity drift connected to offboarding or control failure.
- Non-valuable findings are raw temporal events promoted directly into findings without durable risk semantics. Avoid noisy findings for isolated token creation, policy edits, collaborator additions, old backfill records, or high-volume historical audit events unless they correlate into a current risky state with a clear remediation path.
- Findings should not remain open merely because an event happened once. Prefer current-state checks, graph correlation, stale-finding resolution, suppression, or evidence-only projection when the condition is no longer active or not independently actionable.

## Repository Conventions

- Keep internal deployment and workflow changes scoped to the requested environment or promotion path.
- Prefer existing `infra` validation and workflow patterns over ad-hoc scripts.
- Do not expose secrets, secret names, or credential material in logs, comments, or generated output.
