# LambdaTest

Generated Source Runtime SDK scaffold for `lambdatest`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/lambdatest`
- Health endpoint: `/source-runtimes/health?source_id=lambdatest`
- Source health receipt: `sources/lambdatest/source_health_receipt.json`
- EvidenceCAS reference kind: `lambdatest.evidence_cas_reference`

## Families

- `profile`, emits `lambdatest.profile`, reads `/profiles`
- `resolution`, emits `lambdatest.resolution`, reads `/resolutions`
- `location`, emits `lambdatest.location`, reads `/locations`
- `resource`, emits `lambdatest.resource`, reads `/${config.test_id}`

## Tests

- `go test ./sources/lambdatest ./internal/sourceprojection -count=1`
- `make catalog-check`
