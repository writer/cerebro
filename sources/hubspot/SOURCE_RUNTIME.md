# HubSpot

Generated Source Runtime SDK scaffold for `hubspot`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hubspot`
- Health endpoint: `/source-runtimes/health?source_id=hubspot`
- Source health receipt: `sources/hubspot/source_health_receipt.json`
- EvidenceCAS reference kind: `hubspot.evidence_cas_reference`

## Families

- `users`, emits `hubspot.users`, reads `/v1/users`
- `assets`, emits `hubspot.assets`, reads `/v1/records`
- `audit_events`, emits `hubspot.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/hubspot ./internal/sourceprojection -count=1`
- `make catalog-check`
