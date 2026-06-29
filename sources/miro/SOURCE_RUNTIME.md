# Miro

Generated Source Runtime SDK scaffold for `miro`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/miro`
- Health endpoint: `/source-runtimes/health?source_id=miro`
- Source health receipt: `sources/miro/source_health_receipt.json`
- EvidenceCAS reference kind: `miro.evidence_cas_reference`

## Families

- `users`, emits `miro.users`, reads `/v1/users`
- `projects`, emits `miro.projects`, reads `/v1/projects`
- `audit_events`, emits `miro.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/miro ./internal/sourceprojection -count=1`
- `make catalog-check`
