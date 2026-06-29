# Open Policy Agent

Generated Source Runtime SDK scaffold for `openpolicy`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/openpolicy`
- Health endpoint: `/source-runtimes/health?source_id=openpolicy`
- Source health receipt: `sources/openpolicy/source_health_receipt.json`
- EvidenceCAS reference kind: `openpolicy.evidence_cas_reference`

## Families

- `policy`, emits `openpolicy.policy`, reads `/v1/policies`
- `query`, emits `openpolicy.query`, reads `/v1/query`
- `v1_policy`, emits `openpolicy.v1_policy`, reads `/v1/policies/${config.id}`
- `data`, emits `openpolicy.data`, reads `/v1/data/${config.path}`

## Tests

- `go test ./sources/openpolicy ./internal/sourceprojection -count=1`
- `make catalog-check`
