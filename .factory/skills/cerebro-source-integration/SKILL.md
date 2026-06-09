---
name: cerebro-source-integration
description: "Create, scaffold, or extend Cerebro source connectors under sources/. Use when the user wants to add a new data source integration, build a source connector, implement a preview or runtime sync handler, or wire up source config parsing and validation."
---

# Cerebro Source Integration

## Instructions

### 1. Choose a reference integration

Start from the closest existing integration under `sources/`. Use `sources/github/` for API-based integrations or `sources/okta/` for auth-heavy connectors. Each source follows this file structure:

- `source.go` — `New()` constructor, `Check`, `Discover`, `Read` methods via `sourcecdk`
- `catalog.yaml` — embedded source spec loaded by `sourcecdk.LoadCatalog`
- `source_test.go` — package tests using `httptest` servers
- `testdata/` — JSON fixtures for response decoding

### 2. Implement config parsing

Parse settings from `sourcecdk.Config` with safe defaults, strict validation, and clear error mapping. Wrap validation errors with `sourcecdk.ErrInvalidConfig`:

```go
val := configValue(cfg, "base_url")
if val == "" {
    return fmt.Errorf("%w: base_url is required", sourcecdk.ErrInvalidConfig)
}
```

Run `go test ./<new-source>/... -count=1 -v` after config parsing is complete before proceeding.

### 3. Add preview and runtime sync behavior

Implement `Check`, `Discover`, and `Read` on your `Source` struct following the `sourcecdk` interface. Only implement the behaviors requested. Use `sourcehttp` for all outbound HTTP calls, never a bare `http.Client`.

### 4. Secure network-facing settings

Protect against loopback addresses, unsafe URL schemes, malformed URLs, unbounded response bodies, and pagination loops. Use `internal/sourcehttp` which enforces SSRF protections and body-size limits. Validate with:

```bash
go test ./<new-source>/... -run TestLoopback -count=1 -v
```

### 5. Add package tests

Write table-driven tests for config validation, response decoding, pagination, and error handling. Use `httptest.NewServer` to stub external APIs. Include security boundary cases for URL, host, and auth edge cases.

### 6. Verify

Run focused package tests, then `make verify` when feasible:

```bash
go test ./sources/<new-source>/... -count=1 -v
make verify
```

## Boundaries

- Do not introduce new external dependencies unless explicitly requested.
- Do not add live-service tests unless they are opt-in behind environment variables.
- Keep new integrations within the Source CDK budget. Check `docs/NON_GOALS.md` if proposing shared CDK changes.
