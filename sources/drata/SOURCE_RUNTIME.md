# Drata

Generated Source Runtime SDK scaffold for `drata`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/drata`
- Health endpoint: `/source-runtimes/health?source_id=drata`
- Source health receipt: `sources/drata/source_health_receipt.json`
- EvidenceCAS reference kind: `drata.evidence_cas_reference`

## Families

- `users`, emits `drata.users`, reads `/v1/users`
- `controls`, emits `drata.controls`, reads `/v1/controls`
- `findings`, emits `drata.findings`, reads `/v1/findings`

## Tests

- `go test ./sources/drata ./internal/sourceprojection -count=1`
- `make catalog-check`
