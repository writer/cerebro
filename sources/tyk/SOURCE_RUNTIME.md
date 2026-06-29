# Tyk

Generated Source Runtime SDK scaffold for `tyk`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/tyk`
- Health endpoint: `/source-runtimes/health?source_id=tyk`
- Source health receipt: `sources/tyk/source_health_receipt.json`
- EvidenceCAS reference kind: `tyk.evidence_cas_reference`

## Families

- `key`, emits `tyk.key`, reads `/tyk/keys/`
- `api`, emits `tyk.api`, reads `/tyk/apis/`
- `client`, emits `tyk.client`, reads `/tyk/oauth/clients/${config.apiid}`

## Tests

- `go test ./sources/tyk ./internal/sourceprojection -count=1`
- `make catalog-check`
