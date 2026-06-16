## Summary


## Test Plan


## Known Invariants

- Source connectors use `internal/sourcehttp` for outbound HTTP safety.
- Production body reads are bounded with `io.LimitReader` or streamed.
- Graph Ask queries stay tenant-scoped, read-only, row-limited, and validated.
- Ask deterministic post-processing is not applied to LLM fallback rows.
- Candidate finding lifecycle writes remain atomic and idempotent.
- Public request origin, DPoP `htu`, and trusted proxy handling use the canonical origin helpers.

## Droid Review Context

- Fast local preflight: `make droid-review-preflight`.
- Focus review on changed behavior and the invariants above.
- Escalate to a deep manual Droid tag review for broad auth, graph, source HTTP, or state-machine changes.
- Land with `make land-pr PR=<number>` so Droid finishes before branch deletion.
