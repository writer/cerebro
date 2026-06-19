# Cerebro repo notes

Only repo-specific, non-obvious guidance lives here.

## High-signal context

- This is Writer's original public `cerebro` repo. Do not describe it as a fork or downstream mirror.
- The repo is Go, but many validations are repo-specific and should usually be run via `make`/DevEx wrappers rather than ad-hoc commands.
- Go dependencies are module-managed; avoid dependency changes unless explicitly requested and validate them through the relevant `make` targets.

## Scope discipline

- [`docs/engineering/non-goals.md`](docs/engineering/non-goals.md) is the canonical, indexed list of things Cerebro intentionally does not do. Read it before proposing changes that touch storage shape, the Source CDK budget, the Cypher safety validator, the findings platform contract, the action engine, runtime response, or the platform/security namespace boundary.
- A change that crosses a non-goal must cite the entry, name which "What would change this" criterion has been met, and update `docs/engineering/non-goals.md` in the same PR. Quiet bypass is a review-blocker.

## Preferred validation entrypoints

- Use focused `make` targets while iterating, then `make verify` for broader PR-parity validation.
- Use `make sdk-test` after SDK changes and `make proto-generate-check proto-breaking` after proto changes.
- Prefer `make openapi-check` / `make openapi-sync` instead of hand-editing route placeholders.
- Run `make oss-audit` after public-facing docs/config/example changes, and `make docs-drift-check` when generated docs are touched.

## Generated / contract-governed surfaces

If you touch these areas, expect generated artifacts and compatibility checks:

- OpenAPI contract
- config env-var docs
- graph ontology docs/contracts
- CloudEvents docs/contracts
- report contract docs/contracts
- entity facet docs/contracts
- SDK helper docs/packages
- DevEx codegen catalog

Run `make contracts-check` before finishing broad contract changes, or the corresponding focused `Makefile` `*-check` / `*-compat` target for narrow changes.

## Runtime notes

- Current `main` is the bootstrap service: NATS JetStream as the append log, Postgres as the state store, Neo4j/Aura as the graph projection. There is no in-memory or SQLite fallback in production; routes that need a configured store fail closed when the store is absent. See [`docs/reference/architecture.md`](docs/reference/architecture.md) and the storage section of [`docs/engineering/non-goals.md`](docs/engineering/non-goals.md).
- Some CLI paths use repo-specific env wrappers in `make`, so prefer documented make targets when available.
