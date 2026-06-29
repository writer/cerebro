# Mabl

Generated Source Runtime SDK scaffold for `mabl`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mabl`
- Health endpoint: `/source-runtimes/health?source_id=mabl`
- Source health receipt: `sources/mabl/source_health_receipt.json`
- EvidenceCAS reference kind: `mabl.evidence_cas_reference`

## Families

- `users`, emits `mabl.users`, reads `/v1/users`
- `projects`, emits `mabl.projects`, reads `/v1/projects`
- `repositories`, emits `mabl.repositories`, reads `/v1/repositories`
- `deployments`, emits `mabl.deployments`, reads `/v1/deployments`
- `audit_events`, emits `mabl.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mabl ./internal/sourceprojection -count=1`
- `make catalog-check`
