# CallFire

Generated Source Runtime SDK scaffold for `callfire`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/callfire`
- Health endpoint: `/source-runtimes/health?source_id=callfire`
- Source health receipt: `sources/callfire/source_health_receipt.json`
- EvidenceCAS reference kind: `callfire.evidence_cas_reference`

## Families

- `account`, emits `callfire.account`, reads `/me/account`
- `credential`, emits `callfire.credential`, reads `/me/api/credentials`
- `broadcast`, emits `callfire.broadcast`, reads `/calls/broadcasts`
- `call`, emits `callfire.call`, reads `/calls`

## Tests

- `go test ./sources/callfire ./internal/sourceprojection -count=1`
- `make catalog-check`
