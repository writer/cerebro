# Cerebro repo notes

Only repo-specific, non-obvious guidance lives here.

## High-signal context

- This is Writer's original public `cerebro` repo. Do not describe it as a fork or downstream mirror.
- The repo is Go, but many validations are repo-specific and should usually be run via `make`/DevEx wrappers rather than ad-hoc commands.
- Go dependencies are vendored (`GOFLAGS=-mod=vendor`), so dependency changes should usually be checked with `make vendor-check`.

## Preferred validation entrypoints

- Use `make devex-changed` for diff-aware local preflight.
- Use `make devex-pr` for broader PR-parity validation.
- Prefer `make openapi-check` / `make openapi-sync` instead of hand-editing route placeholders.
- Run `python3 scripts/oss_audit.py` after public-facing docs/config/example changes.

## Generated / contract-governed surfaces

If you touch these areas, expect generated artifacts and compatibility checks:

- OpenAPI contract
- config env-var docs
- graph ontology docs/contracts
- CloudEvents docs/contracts
- report contract docs/contracts
- entity facet docs/contracts
- Agent SDK docs/contracts/packages
- DevEx codegen catalog

Check the corresponding `Makefile` `*-check` / `*-compat` targets before finishing.

## Runtime notes

- Full-featured runs expect Snowflake, but local SQLite mode exists for lighter local development.
- Some CLI paths use repo-specific env wrappers in `make`, so prefer documented make targets when available.
