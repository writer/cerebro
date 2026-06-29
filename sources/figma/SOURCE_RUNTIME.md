# Figma

Generated Source Runtime SDK scaffold for `figma`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/figma`
- Health endpoint: `/source-runtimes/health?source_id=figma`
- Source health receipt: `sources/figma/source_health_receipt.json`
- EvidenceCAS reference kind: `figma.evidence_cas_reference`

## Families

- `users`, emits `figma.users`, reads `/v1/users`
- `projects`, emits `figma.projects`, reads `/v1/projects`
- `audit_events`, emits `figma.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/figma ./internal/sourceprojection -count=1`
- `make catalog-check`
