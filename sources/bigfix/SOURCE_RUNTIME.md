# BigFix

Generated Source Runtime SDK scaffold for `bigfix`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bigfix`
- Health endpoint: `/source-runtimes/health?source_id=bigfix`
- Source health receipt: `sources/bigfix/source_health_receipt.json`
- EvidenceCAS reference kind: `bigfix.evidence_cas_reference`

## Families

- `computers`, emits `bigfix.computers`, reads `/api/computers`
- `sites`, emits `bigfix.sites`, reads `/api/sites`
- `analyses`, emits `bigfix.analyses`, reads `/api/analyses`

## Tests

- `go test ./sources/bigfix ./internal/sourceprojection -count=1`
- `make catalog-check`
