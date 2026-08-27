# Cerebro repo notes

Only repo-specific, non-obvious guidance lives here.

## High-signal context

- This is Writer's original public `cerebro` repo. Do not describe it as a fork or downstream mirror.
- This is a dual-runtime repo mid-migration, not a Go repo. The Go service (`internal/`, `apps/`, `sources/`) and the Rust workspace (`crates/`, ~20 crates) run side by side: Rust is the authority for organizational graph projection on promoted source families, while Go retains legacy projection and most write paths. Authority cutover is gated per family; see [`docs/engineering/rust-organizational-platform.md`](docs/engineering/rust-organizational-platform.md) and [`docs/engineering/rust-graph-read-migration-plan.md`](docs/engineering/rust-graph-read-migration-plan.md) before assuming either runtime owns a path.
- Go dependencies are module-managed and Rust dependencies are `cargo-deny`-policed; avoid dependency changes unless explicitly requested and validate them through the relevant `make` targets (`make rust-deny` for Rust).
- Many validations are repo-specific and should usually be run via `make`/DevEx wrappers rather than ad-hoc commands.

## Scope discipline

- [`docs/engineering/non-goals.md`](docs/engineering/non-goals.md) is the canonical, indexed list of things Cerebro intentionally does not do. Read it before proposing changes that touch storage shape, the Source CDK budget, the Cypher safety validator, the findings platform contract, the action engine, runtime response, or the platform/security namespace boundary.
- A change that crosses a non-goal must cite the entry, name which "What would change this" criterion has been met, and update `docs/engineering/non-goals.md` in the same PR. Quiet bypass is a review-blocker.

## Preferred validation entrypoints

- Use focused `make` targets while iterating, then `make verify` for broader PR-parity validation.
- `make changed-check` selects and runs the focused validation commands implied by your changed paths (`REVIEW_BASE`/`REVIEW_HEAD` override the diff range) — prefer it over guessing which checks apply.
- Use `make sdk-test` after SDK changes and `make proto-generate-check proto-breaking` after proto changes.
- For Rust changes, the focused loop is `make rust-fmt-check rust-clippy rust-test`; embedded/Wasm kernels have their own `*-check` targets in the Makefile.
- Prefer `make openapi-check` / `make openapi-sync` instead of hand-editing route placeholders.
- Run `make oss-audit` after public-facing docs/config/example changes, and `make docs-drift-check` when generated docs are touched.
- Run `make agent-docs-check` after editing this file, `AGENTS.md`, or any agent skill — it verifies that referenced make targets and repo docs actually exist.

## Generated / contract-governed surfaces

Never hand-edit generated outputs; regenerate them with the owning `make` target. Generated roots include `crates/cerebro-platform/src/generated/`, `sdk/typescript/src/generated/`, `sdk/go/cerebroapi/genproto/`, and `gen/`. If you touch these areas, expect generated artifacts and compatibility checks:

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
- The Rust organizational runtime consumes committed events directly from JetStream; Go cannot submit event payloads to the Rust projector, and promoted families return no Go projection result. Do not add alternate Go entry points that could restore a retired writer.
- Some CLI paths use repo-specific env wrappers in `make`, so prefer documented make targets when available.
- For end-to-end verification against a real local stack (NATS + Postgres + Neo4j via Docker), use `make agent-onboard-e2e`; it boots the stack, runs the onboarding plan, and writes a redacted receipt.
