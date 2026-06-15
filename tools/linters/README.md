# cerebrolint

`cerebrolint` is a Go `multichecker` that enforces Cerebro's architectural
invariants documented in `docs/NON_GOALS.md` and this directory.

Each analyzer lives in its own package under `tools/linters/<name>/` and is
tested with `golang.org/x/tools/go/analysis/analysistest` against golden
fixtures in `testdata/src/a/a.go`.

## Run

```
cd tools/linters
go test ./...                       # runs analyzer unit tests
go run ./cerebrolint ../../...      # runs all analyzers against the main module
```

Or from the repo root:

```
make check-structural
```

## Authoring a new analyzer

1. Create `tools/linters/<name>/<name>.go` exporting `var Analyzer = &analysis.Analyzer{...}`.
2. Create `tools/linters/<name>/<name>_test.go` with an `analysistest.Run` call.
3. Add fixtures under `testdata/src/a/a.go` annotated with `// want "..."`.
4. Register the analyzer in `tools/linters/cerebrolint/main.go`.
5. Update `docs/NON_GOALS.md` if the rule enforces or changes a documented boundary.

Every rule must have a precise diagnostic that points at the exact AST node
and (where possible) a suggested fix.
