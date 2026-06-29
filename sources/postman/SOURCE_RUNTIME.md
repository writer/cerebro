# Postman

Generated Source Runtime SDK scaffold for `postman`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/postman`
- Health endpoint: `/source-runtimes/health?source_id=postman`
- Source health receipt: `sources/postman/source_health_receipt.json`
- EvidenceCAS reference kind: `postman.evidence_cas_reference`

## Families

- `collections`, emits `postman.collections`, reads `/collections`
- `environments`, emits `postman.environments`, reads `/environments`
- `audit_events`, emits `postman.audit_events`, reads `/audit/events`

## Tests

- `go test ./sources/postman ./internal/sourceprojection -count=1`
- `make catalog-check`
