# Cerebro - Business Intelligence Engine

## Quick Reference
```bash
make build                # Build the Go binary
make test                 # Run tests
make lint                 # Run linters
make docker-build         # Build Docker image
make run                  # Run locally
```

## Architecture
- **Language**: Go
- **Event ingestion**: NATS JetStream (CloudEvents format)
- **Analytics store**: ClickHouse
- **Deployment**: Docker → k3s via ArgoCD
- **Connected to**: Ensemble (agent platform), Platform (core SaaS)

## Purpose
Cerebro is the "brain" of Writer — it ingests organizational events, processes them through analyzers, and produces business intelligence. Think of it as giving a 2-person startup the BI capabilities of a much larger company.

## Key Directories
- `cmd/` — CLI entrypoints
- `api/` — HTTP API handlers
- `internal/` — Core business logic, analyzers, event processing
- `policies/` — Policy definitions
- `scripts/` — Operational scripts

## Conventions
- Follow idiomatic Go (gofmt, golint, govet)
- Use CloudEvents spec for all event types
- ClickHouse tables use ReplacingMergeTree — always query with FINAL for dedup
- All config via environment variables (see `internal/config/`)
