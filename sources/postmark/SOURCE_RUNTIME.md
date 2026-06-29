# Postmark

Generated Source Runtime SDK scaffold for `postmark`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/postmark`
- Health endpoint: `/source-runtimes/health?source_id=postmark`
- Source health receipt: `sources/postmark/source_health_receipt.json`
- EvidenceCAS reference kind: `postmark.evidence_cas_reference`

## Families

- `servers`, emits `postmark.servers`, reads `/servers`
- `domains`, emits `postmark.domains`, reads `/domains`
- `audit_events`, emits `postmark.audit_events`, reads `/audit/events`

## Tests

- `go test ./sources/postmark ./internal/sourceprojection -count=1`
- `make catalog-check`
