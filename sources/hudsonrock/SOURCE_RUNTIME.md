# Hudson Rock

Generated Source Runtime SDK scaffold for `hudsonrock`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hudsonrock`
- Health endpoint: `/source-runtimes/health?source_id=hudsonrock`
- Source health receipt: `sources/hudsonrock/source_health_receipt.json`
- EvidenceCAS reference kind: `hudsonrock.evidence_cas_reference`

## Families

- `infostealers`, emits `hudsonrock.infostealers`, reads `/infostealers`
- `domains`, emits `hudsonrock.domains`, reads `/domains`
- `audit_events`, emits `hudsonrock.audit_events`, reads `/audit-events`

## Tests

- `go test ./sources/hudsonrock ./internal/sourceprojection -count=1`
- `make catalog-check`
