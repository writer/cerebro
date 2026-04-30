---
name: cerebro-creation
description: Implement focused Cerebro issues or PR follow-ups from Droid Create workflows.
---

# Cerebro Creation

## Instructions

1. Read the triggering issue/PR, existing comments, reviews, and failing checks before editing.
2. Identify the smallest production-quality change that satisfies the request.
3. Match existing Go package boundaries, source connector patterns, and Makefile validation flow.
4. Add focused tests for new behavior or any bug fixed.
5. Run targeted tests first, then `make verify` when feasible.
6. Leave changes in the working tree; CI handles commit, push, and PR creation.

## Stop Conditions

- Stop if the request requires secrets, production access, or unclear external service behavior.
- Stop if the task would require merging PRs or pushing directly to the default branch.
