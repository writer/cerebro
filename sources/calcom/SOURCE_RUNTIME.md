# Cal.com

Generated Source Runtime SDK scaffold for `calcom`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/calcom`
- Health endpoint: `/source-runtimes/health?source_id=calcom`
- Source health receipt: `sources/calcom/source_health_receipt.json`
- EvidenceCAS reference kind: `calcom.evidence_cas_reference`

## Families

- `bookings`, emits `calcom.bookings`, reads `/bookings`
- `users`, emits `calcom.users`, reads `/users`
- `audit_events`, emits `calcom.audit_events`, reads `/audit-events`

## Tests

- `go test ./sources/calcom ./internal/sourceprojection -count=1`
- `make catalog-check`
