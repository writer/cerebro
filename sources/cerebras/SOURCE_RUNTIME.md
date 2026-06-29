# Cerebras

Generated Source Runtime SDK scaffold for `cerebras`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cerebras`
- Health endpoint: `/source-runtimes/health?source_id=cerebras`
- Source health receipt: `sources/cerebras/source_health_receipt.json`
- EvidenceCAS reference kind: `cerebras.evidence_cas_reference`

## Families

- `projects`, emits `cerebras.projects`, reads `/v1/projects`
- `api_keys`, emits `cerebras.api_keys`, reads `/v1/api-keys`
- `usage_reports`, emits `cerebras.usage_reports`, reads `/v1/usage`
- `model_deployments`, emits `cerebras.model_deployments`, reads `/v1/deployments`

## Tests

- `go test ./sources/cerebras ./internal/sourceprojection -count=1`
- `make catalog-check`
