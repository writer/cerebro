---
name: review-guidelines
description: Repository-specific Cerebro review invariants and triage guidance for Droid code and security reviews.
---

# Cerebro Review Guidelines

Use this context to keep Droid reviews focused and fast.

## Known Invariants

- Source connectors must use `internal/sourcehttp` for outbound HTTP safety; do not reintroduce connector-local `http.Client`, transport, body-read, SSRF, or DNS-rebinding logic.
- Production `io.ReadAll` calls must read from `io.LimitReader` or be replaced with streaming code. The fast local check is `make droid-review-preflight`.
- Graph Ask Cypher must be tenant-scoped, read-only, row-limited, and validated before execution. Prefer deterministic query templates for supported intents.
- Ask post-processing may only run for deterministic templates; LLM fallback rows must not be reshaped by deterministic Go post-processing.
- Candidate finding state transitions must be atomic and idempotent. Avoid split read-then-write state changes unless a store method owns the compare-and-swap.
- Device auth request origins, DPoP `htu`, client IP, and proxy-derived headers must flow through the canonical request-origin helpers.

## Review Triage

- Prioritize concrete correctness, authorization, tenant isolation, SSRF/body-size, and state-transition bugs over style suggestions.
- Treat matching local regression coverage as strong evidence; ask for focused tests only when the behavior can regress.
- If a finding matches an invariant above, cite the invariant and the exact local command that would have caught it.
- Keep comments scoped to changed code. Avoid broad architecture restatements when a PR changes only tests, docs, or workflow plumbing.
