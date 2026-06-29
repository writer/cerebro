# Tray.io

Generated Source Runtime SDK scaffold for `tray_io`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/tray_io`
- Health endpoint: `/source-runtimes/health?source_id=tray_io`
- Source health receipt: `sources/tray_io/source_health_receipt.json`
- EvidenceCAS reference kind: `tray_io.evidence_cas_reference`

## Families

- `users`, emits `tray_io.users`, reads `/v1/users`
- `projects`, emits `tray_io.projects`, reads `/v1/projects`
- `repositories`, emits `tray_io.repositories`, reads `/v1/repositories`
- `deployments`, emits `tray_io.deployments`, reads `/v1/deployments`
- `audit_events`, emits `tray_io.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/tray_io ./internal/sourceprojection -count=1`
- `make catalog-check`
