# Contributing to Cerebro

Thanks for contributing.

## Development setup

1. Install Go `1.25.x`.
2. Clone the repository.
   ```bash
   git clone https://github.com/evalops/cerebro.git
   cd cerebro
   ```
3. Run:

```bash
make setup
```

## Local mode (no Snowflake)

You can run Cerebro without Snowflake credentials for local development.

```bash
unset SNOWFLAKE_PRIVATE_KEY SNOWFLAKE_ACCOUNT SNOWFLAKE_USER
export CEREBRO_DB_PATH=.cerebro/cerebro.db
make serve
```

In this mode, findings persist to local SQLite and some Snowflake-dependent features (for example, data-lake queries and security graph) are limited or disabled.

## Code quality checks

Before opening a PR, run:

```bash
go test ./...
golangci-lint run ./...
go vet ./...
make policy-validate
```

## Dependency and `vendor/` strategy

This repository keeps `vendor/` committed for reproducible builds and OSS consumers in restricted environments.

If you change dependencies:

```bash
go mod tidy
go mod vendor
```

Make sure `go.mod`, `go.sum`, and `vendor/` are all committed together.

## Security checks

For source security scanning:

```bash
$(go env GOPATH)/bin/gosec -severity medium -confidence medium -exclude-generated ./...
$(go env GOPATH)/bin/govulncheck ./...
```

For built artifact scanning:

```bash
make security-scan-built
```
