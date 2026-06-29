# Segment

Generated Source Runtime SDK scaffold for `segment`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/segment`
- Health endpoint: `/source-runtimes/health?source_id=segment`
- Source health receipt: `sources/segment/source_health_receipt.json`
- EvidenceCAS reference kind: `segment.evidence_cas_reference`

## Families

- `workspaces`, emits `segment.workspaces`, reads `/workspaces`
- `users`, emits `segment.users`, reads `/users`
- `sources`, emits `segment.sources`, reads `/sources`

## Tests

- `go test ./sources/segment ./internal/sourceprojection -count=1`
- `make catalog-check`
