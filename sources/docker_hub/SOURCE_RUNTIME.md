# Docker Hub

Generated Source Runtime SDK scaffold for `docker_hub`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/docker_hub`
- Health endpoint: `/source-runtimes/health?source_id=docker_hub`
- Source health receipt: `sources/docker_hub/source_health_receipt.json`
- EvidenceCAS reference kind: `docker_hub.evidence_cas_reference`

## Families

- `repositories`, emits `docker_hub.repositories`, reads `/v1/repositories`
- `users`, emits `docker_hub.users`, reads `/v1/users`
- `audit_events`, emits `docker_hub.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/docker_hub ./internal/sourceprojection -count=1`
- `make catalog-check`
