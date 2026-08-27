---
name: cerebro-creation
description: Implement focused Cerebro issues or PR follow-ups. Use for bug fixes, review feedback, and small scoped features in this repo.
---

# Cerebro Creation

## Instructions

1. Read the triggering issue/PR, existing comments, reviews, and failing checks before editing.
2. Identify the smallest production-quality change that satisfies the request.
3. Match existing package boundaries and patterns: Go service code in `internal/`/`apps/`/`sources/`, Rust workspace code in `crates/`. Check which runtime owns the path before editing — see the runtime notes in [CLAUDE.md](../../../CLAUDE.md).
4. Add focused tests for new behavior or any bug fixed.
5. Run `make changed-check` to select and run the validation implied by your diff; run `make verify` for PR-parity when feasible.

## Stop Conditions

- Stop if the request requires secrets, production access, or unclear external service behavior.
- Stop if the task would require merging PRs or pushing directly to the default branch.
- Stop and cite the entry if the change would cross an item in [docs/engineering/non-goals.md](../../../docs/engineering/non-goals.md).
