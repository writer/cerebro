# Secureframe

Generated Source Runtime SDK scaffold for `secureframe`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/secureframe`
- Health endpoint: `/source-runtimes/health?source_id=secureframe`
- Source health receipt: `sources/secureframe/source_health_receipt.json`
- EvidenceCAS reference kind: `secureframe.evidence_cas_reference`

## Families

- `users`, emits `secureframe.users`, reads `/v1/users`
- `controls`, emits `secureframe.controls`, reads `/v1/controls`
- `findings`, emits `secureframe.findings`, reads `/v1/findings`

## Tests

- `go test ./sources/secureframe ./internal/sourceprojection -count=1`
- `make catalog-check`
