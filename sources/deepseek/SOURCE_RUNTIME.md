# DeepSeek

Generated Source Runtime SDK scaffold for `deepseek`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/deepseek`
- Health endpoint: `/source-runtimes/health?source_id=deepseek`
- Source health receipt: `sources/deepseek/source_health_receipt.json`
- EvidenceCAS reference kind: `deepseek.evidence_cas_reference`

## Families

- `model_catalog`, emits `deepseek.model_catalog`, reads `/models`
- `account_balances`, emits `deepseek.account_balances`, reads `/user/balance`

## Tests

- `go test ./sources/deepseek ./internal/sourceprojection -count=1`
- `make catalog-check`
