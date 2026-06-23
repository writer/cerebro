# CyberArk Conjur

Generated Source Runtime SDK scaffold for `conjur`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/conjur`
- Health endpoint: `/source-runtimes/health?source_id=conjur`
- Source health receipt: `sources/conjur/source_health_receipt.json`
- EvidenceCAS reference kind: `conjur.evidence_cas_reference`

## Families

- `resource`, emits `conjur.resource`, reads `/resources`
- `authenticator`, emits `conjur.authenticator`, reads `/authenticators`
- `resource_2`, emits `conjur.resource_2`, reads `/resources/${config.account}`
- `resource_3`, emits `conjur.resource_3`, reads `/resources/${config.account}/${config.kind}`

## Tests

- `go test ./sources/conjur ./internal/sourceprojection -count=1`
- `make catalog-check`
