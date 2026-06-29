# Pendo

Generated Source Runtime SDK scaffold for `pendo`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/pendo`
- Health endpoint: `/source-runtimes/health?source_id=pendo`
- Source health receipt: `sources/pendo/source_health_receipt.json`
- EvidenceCAS reference kind: `pendo.evidence_cas_reference`

## Families

- `account`, emits `pendo.account`, reads `/accounts`
- `feature`, emits `pendo.feature`, reads `/features`
- `user`, emits `pendo.user`, reads `/users`
- `search`, emits `pendo.search`, reads `/search`

## Tests

- `go test ./sources/pendo ./internal/sourceprojection -count=1`
- `make catalog-check`
