# Microsoft Entra ID

Generated Source Runtime SDK scaffold for `microsoft_entra_id`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/microsoft_entra_id`
- Health endpoint: `/source-runtimes/health?source_id=microsoft_entra_id`
- Source health receipt: `sources/microsoft_entra_id/source_health_receipt.json`
- EvidenceCAS reference kind: `microsoft_entra_id.evidence_cas_reference`

## Families

- `users`, emits `microsoft_entra_id.users`, reads `/v1/users`
- `groups`, emits `microsoft_entra_id.groups`, reads `/v1/groups`
- `audit_events`, emits `microsoft_entra_id.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/microsoft_entra_id ./internal/sourceprojection -count=1`
- `make catalog-check`
