---
name: review-guidelines
description: Repository-specific Cerebro review invariants and triage guidance for deterministic and manual reviews.
---

# Cerebro Review Guidelines

Use this context to keep repository reviews focused and evidence-based.
Review pass contracts live in `.factory/review-passes.json`; review memory lives in `.factory/review-memory.json`. Use both as context, but validate every claim against changed code.

## Known Invariants

- Source connectors must use `internal/sourcehttp` for outbound HTTP safety; do not reintroduce connector-local `http.Client`, transport, body-read, SSRF, or DNS-rebinding logic.
- Production `io.ReadAll` calls must read from `io.LimitReader` or be replaced with streaming code. The fast local check is `make review-invariants`.
- The required deterministic review gate runs invariant, structural, architecture, scanner, vulnerability, and leak checks; manual context is advisory and must not replace validating exploitability.
- Graph Ask Cypher must be tenant-scoped, read-only, row-limited, and validated before execution. Prefer deterministic query templates for supported intents.
- Ask post-processing may only run for deterministic templates; LLM fallback rows must not be reshaped by deterministic Go post-processing.
- Candidate finding state transitions must be atomic and idempotent. Avoid split read-then-write state changes unless a store method owns the compare-and-swap.
- Device auth request origins, DPoP `htu`, client IP, and proxy-derived headers must flow through the canonical request-origin helpers.

## Review Triage

- Prioritize concrete correctness, authorization, tenant isolation, SSRF/body-size, and state-transition bugs over style suggestions.
- Treat matching local regression coverage as strong evidence; ask for focused tests only when the behavior can regress.
- If a finding matches an invariant above, cite the invariant and the exact local command that would have caught it.
- Run reviews as bounded subpasses: scanner validation, changed behavior, tenant/security invariants, tests/evals, workflow permissions, feedback validation, and CI/log context. State which pass found the issue.
- Keep comments scoped to changed code. Avoid broad architecture restatements when a PR changes only tests, docs, or workflow plumbing.
- Use `scripts/droid_review_context.py` only for explicitly requested manual task context: execute passes in order, attach evidence per pass, and classify each finding by pass/invariant.
