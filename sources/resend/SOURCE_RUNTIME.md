# Resend

Generated Source Runtime SDK scaffold for `resend`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/resend`
- Health endpoint: `/source-runtimes/health?source_id=resend`
- Source health receipt: `sources/resend/source_health_receipt.json`
- EvidenceCAS reference kind: `resend.evidence_cas_reference`

## Families

- `domains`, emits `resend.domains`, reads `/domains`
- `api_keys`, emits `resend.api_keys`, reads `/api-keys`
- `audit_events`, emits `resend.audit_events`, reads `/audit/events`

## Tests

- `go test ./sources/resend ./internal/sourceprojection -count=1`
- `make catalog-check`
