# Stripe

Generated Source Runtime SDK scaffold for `stripe`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/stripe`
- Health endpoint: `/source-runtimes/health?source_id=stripe`
- Source health receipt: `sources/stripe/source_health_receipt.json`
- EvidenceCAS reference kind: `stripe.evidence_cas_reference`

## Families

- `users`, emits `stripe.users`, reads `/v1/users`
- `assets`, emits `stripe.assets`, reads `/v1/records`
- `audit_events`, emits `stripe.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/stripe ./internal/sourceprojection -count=1`
- `make catalog-check`
