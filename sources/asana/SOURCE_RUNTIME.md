# Asana

Generated Source Runtime SDK scaffold for `asana`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/asana`
- Health endpoint: `/source-runtimes/health?source_id=asana`
- Source health receipt: `sources/asana/source_health_receipt.json`
- EvidenceCAS reference kind: `asana.evidence_cas_reference`

## Families

- `event`, emits `asana.event`, reads `/events`
- `membership`, emits `asana.membership`, reads `/memberships`
- `role`, emits `asana.role`, reads `/roles`
- `user`, emits `asana.user`, reads `/users`

## Tests

- `go test ./sources/asana ./internal/sourceprojection -count=1`
- `make catalog-check`
