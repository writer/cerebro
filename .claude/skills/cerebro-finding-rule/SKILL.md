---
name: cerebro-finding-rule
description: Design or change a Cerebro finding rule. Use for new durable rules, rule lifecycle fixes, fingerprint changes, or promoting source evidence into findings.
---

# Cerebro Finding Rule

The full design rationale lives in the "Finding Rule Design Notes" section of
[AGENTS.md](../../../AGENTS.md). This skill is the working checklist.

## Decide before writing the matcher

1. Is this a durable, remediable risk state — not a raw temporal event? If the
   condition stops being independently actionable when the event ages out,
   model it as evidence or graph context instead of a finding.
2. Choose the anchor first. Source-state rules anchor on durable provider IDs
   turned into tenant-scoped URNs; graph-anchored rules anchor on graph
   entities or paths. Never fingerprint on event IDs, timestamps, run IDs,
   pagination IDs, or vendor alert IDs unless that vendor object is itself the
   durable remediable state.
3. Canonicalize provider-controlled identifiers before they enter URNs, event
   IDs, graph anchors, or fingerprints. Preserve raw provider IDs as
   attributes for investigation.

## Every durable rule needs

- Explicit `Lifecycle` semantics and stable `FingerprintFields`.
- `OpenAnchor` and `CloseOnEvent` that meet in the middle: the close event must
  produce the same anchor stored on the open finding, or the rule must not
  claim closeout support.
- Required attributes, control refs, false-positive guidance, and a runbook.
- Close paths for deprovisioned/offboarded/inactive resources unless the
  finding is explicitly about unsafe removal.
- Positive-evidence semantics: missing or unknown upstream data is unknown,
  not a failing control.

## Test matrix (all of these)

- Positive open; negative non-open; required attributes present.
- Stable fingerprint and reopen behavior.
- Remediation close; deprovision/offboard close where applicable.
- A counterexample proving unrelated or contextless events do not close the
  finding.

## Validate

- Focused package tests, then `make finding-dsl-check policy-rule-check policy-mapping-check detection-catalog-check`.
- `make changed-check` for the diff-selected remainder; `make contracts-check`
  if contract-governed docs moved.
