# Stability AI

Generated Source Runtime SDK scaffold for `stability_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/stability_ai`
- Health endpoint: `/source-runtimes/health?source_id=stability_ai`
- Source health receipt: `sources/stability_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `stability_ai.evidence_cas_reference`

## Families

- `engines`, emits `stability_ai.engines`, reads `/v1/engines/list`
- `account`, emits `stability_ai.account`, reads `/v1/user/account`
- `account_balance`, emits `stability_ai.account_balance`, reads `/v1/user/balance`

## Tests

- `go test ./sources/stability_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
