# Microsoft Teams

Generated Source Runtime SDK scaffold for `microsoft_teams`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/microsoft_teams`
- Health endpoint: `/source-runtimes/health?source_id=microsoft_teams`
- Source health receipt: `sources/microsoft_teams/source_health_receipt.json`
- EvidenceCAS reference kind: `microsoft_teams.evidence_cas_reference`

## Families

- `users`, emits `microsoft_teams.users`, reads `/v1/users`
- `content_assets`, emits `microsoft_teams.content_assets`, reads `/v1/resources`
- `audit_events`, emits `microsoft_teams.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/microsoft_teams ./internal/sourceprojection -count=1`
- `make catalog-check`
