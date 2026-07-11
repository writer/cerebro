# Compliance Parity Rollout

## Cohort gates

Advance one caller and tenant cohort at a time.

1. **Fixtures:** canonical hashes, result axes, reason codes, and legacy mappings
   match frozen conformance cases.
2. **Replay:** an empty Postgres projection rebuilds the same revisions, counts,
   chunks, and hashes.
3. **Shadow:** canonical collection and evaluation run without serving results.
   Every required input is complete and every difference has a reason.
4. **Read:** the cohort reads canonical projections while writes remain on the
   current path.
5. **Write:** the cohort creates canonical plans and runs. Compatibility reads
   continue to work.
6. **Audit:** package rebuild, engagement access, redaction, and receipt checks
   pass.
7. **Default:** canonical reads become the cohort default after two complete
   assessment cycles.
8. **Retirement:** remove a legacy calculation only when its caller count is zero.

## Required switches

Maintain separate switches for:

- canonical reads
- assessment creation
- monitor scheduling
- package delivery

Do not use one global switch. A package-delivery incident must not disable safe
assessment reads.

## Difference handling

Classify each shadow difference as:

- expected compatibility mapping
- input completeness difference
- source-trust difference
- evidence-scope or period difference
- evaluator defect
- legacy defect
- unresolved

An unresolved difference blocks the cohort. Do not normalize it away or treat the
legacy result as authoritative by default.

## Rollback

1. Disable the narrowest affected switch.
2. Keep canonical events, completed runs, review revisions, and package manifests.
3. Route reads to the previous adapter for the affected cohort.
4. Rebuild and compare the canonical projection from its last verified receipt.
5. Record the rollback owner, threshold crossed, affected caller, and recovery
   decision in the internal incident channel.
6. Resume only after replay and parity checks pass for the affected cohort.

Rollback never deletes canonical history or mutates a completed run.

