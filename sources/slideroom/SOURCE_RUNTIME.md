# SlideRoom

Generated Source Runtime SDK scaffold for `slideroom`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/slideroom`
- Health endpoint: `/source-runtimes/health?source_id=slideroom`
- Source health receipt: `sources/slideroom/source_health_receipt.json`
- EvidenceCAS reference kind: `slideroom.evidence_cas_reference`

## Families

- `name`, emits `slideroom.name`, reads `/api/v2/applicant/attributes/names`
- `attributes_name`, emits `slideroom.attributes_name`, reads `/api/v2/application/attributes/names`
- `export`, emits `slideroom.export`, reads `/api/v2/export/${config.token}`

## Tests

- `go test ./sources/slideroom ./internal/sourceprojection -count=1`
- `make catalog-check`
