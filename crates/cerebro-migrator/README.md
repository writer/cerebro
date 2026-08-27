# Cerebro migration planner

`cerebro-migrator` discovers the repository-owned Go dependency graph, plans
content-addressed migration batches, and applies an exact-file deletion manifest
only after a trusted qualification boundary marks every selected unit eligible.

The planner and discovery commands are read-only. A generated candidate is not
deletion authority.

## Discover the Go graph

```sh
go list -deps -json ./cmd/... | \
  cargo run --locked -p cerebro-migrator -- \
    discover --module github.com/writer/cerebro --output /tmp/go-graph.json
```

Absolute checkout directories are removed from the graph contract. Package
paths and digests are portable across worktrees.

## Generate and plan a projection batch

```sh
go run ./tools/rustcarve \
  -root . \
  -projection-batches \
  -exclude-paths tools/rustcarve/testdata/projection-batch-pr-2827-exclusions.json \
  -out /tmp/projection-batch

cargo run --locked -p cerebro-migrator -- \
  plan \
  --input /tmp/projection-batch/projection-plan-request.json \
  --output /tmp/projection-batch/batch-plan.json
```

Planning computes the deterministic maximum-weight prerequisite closure.
Blocked units and units whose prerequisites cannot be selected remain excluded.

## Deletion commands

The deletion workflow has three explicit stages:

```sh
cargo run --locked -p cerebro-migrator -- \
  bind-manifest --root /absolute/repository \
  --input qualified-plan-bundle.json \
  --output deletion-manifest.json

cargo run --locked -p cerebro-migrator -- \
  verify --root /absolute/repository \
  --input deletion-manifest.json \
  --output deletion-preflight.json

cargo run --locked -p cerebro-migrator -- \
  apply --root /absolute/repository \
  --input deletion-manifest.json > deletion-receipt.json
```

`bind-manifest` requires a clean checkout at the exact plan base and binds the
current bytes of every tracked regular-file target. `verify` performs the full
preflight without mutation. `apply` repeats that full preflight, removes only
the exact manifest files, and writes the content-addressed receipt to stdout.

Patterns, path traversal, symbols, directories, symlinks, untracked files,
dirty worktrees, base drift, and content drift fail closed.

## Qualification boundary

The current repository does not yet have a trusted export containing every
persisted family qualification receipt required to retire a projection writer.
Consequently, public planning, unit parsing, manifest binding, verification,
and apply reject `deletion_eligible`, even when an operator supplies a matching
content digest. The executor's successful deletion path is exercised through a
crate-private test authority only.

A production qualifier must verify complete family-scoped fixture parity,
authenticated collection, append and checkpoint ordering, restart, live
projection parity, exact runtime revision, product read, promotion approval,
recovery, and Rust authority evidence before it can construct a qualified unit.
