## Summary


## Test Plan


## Known Invariants

- Source connectors use `internal/sourcehttp` for outbound HTTP safety.
- Production body reads are bounded with `io.LimitReader` or streamed.
- Graph Ask queries stay tenant-scoped, read-only, row-limited, and validated.
- Ask deterministic post-processing is not applied to LLM fallback rows.
- Candidate finding lifecycle writes remain atomic and idempotent.
- Public request origin, DPoP `htu`, and trusted proxy handling use the canonical origin helpers.

## Deterministic Review

- Fast local invariant check: `make review-invariants`.
- Focus review on changed behavior and the invariants above.
- The required `deterministic-review` check runs the exact PR range through invariant, contract, structural, architecture, scanner, vulnerability, leak, and workflow-permission gates.
- Use a manual `@droid` task only when explicitly requested for broad auth, graph, source HTTP, or state-machine investigation; it is not an automatic merge gate.
- Land with `make land-pr PR=<number>` so the deterministic review check and required checks pass before branch deletion.
