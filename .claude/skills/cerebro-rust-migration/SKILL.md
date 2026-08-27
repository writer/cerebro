---
name: cerebro-rust-migration
description: Work on the Go-to-Rust migration - porting compatibility callers, family authority promotion, parity evidence, or Rust read API capabilities.
---

# Cerebro Rust Migration

Authority cutover is family-by-family and fails closed. Before editing,
read [docs/engineering/rust-organizational-platform.md](../../../docs/engineering/rust-organizational-platform.md)
(authority model, compatibility port, remaining-callers table) and
[docs/engineering/rust-graph-read-migration-plan.md](../../../docs/engineering/rust-graph-read-migration-plan.md)
(sequencing and capability gaps).

## Invariants that gate every change

- A persisted `(tenant, source, family)` authority record selects exactly one
  writer, including replay/refetch/device/CLI/orchestrator entry points. Do
  not add alternate Go entry points that could restore a retired writer.
- Rust authority requires a commit receipt and fails closed. The
  compatibility mapper is parity evidence, never a write fallback for a
  promoted family.
- Promotion is driven by stored parity receipts: `cerebro-platform
  evaluate-family` evaluates, `promote-family` records authority,
  `show-authority` reads the effective record.

## Porting a compatibility caller

1. Find the caller's row in the remaining-callers table; it names the exact
   Rust read-API capability gap blocking it.
2. Map the caller's entity kinds and relations into the organizational schema
   before touching query code; path callers additionally need URN-keyed
   `FindPaths` entry points.
3. Migrated callers must stop referencing `ports.RawCypherQueryStore` — that
   reference is what marks a caller as legacy.
4. Update the remaining-callers table in the same PR.

## Parity and validation

- `make fixture-oracle-generate` regenerates the checked Go fixture oracle
  consumed by Rust parity tests.
- `make projection-parity-test` compares legacy and Rust semantic projection
  facts over the same provider records.
- Focused Rust loop: `make rust-fmt-check rust-clippy rust-test`; benchmarks
  via `make rust-organizational-platform-benchmark` when projection cost is
  touched.
- `make changed-check` for the diff-selected remainder.

## Public PR safety

Keep tenant names, environment details, candidate counts, and rollout
observations out of public PR metadata — see "Public PR Data Safety" in
[AGENTS.md](../../../AGENTS.md).
