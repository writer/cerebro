# Together AI

Generated Source Runtime SDK scaffold for `together_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/together_ai`
- Health endpoint: `/source-runtimes/health?source_id=together_ai`
- Source health receipt: `sources/together_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `together_ai.evidence_cas_reference`

## Families

- `projects`, emits `together_ai.projects`, reads `/v1/projects`
- `api_keys`, emits `together_ai.api_keys`, reads `/v1/api-keys`
- `usage_reports`, emits `together_ai.usage_reports`, reads `/v1/usage`
- `fine_tuning_jobs`, emits `together_ai.fine_tuning_jobs`, reads `/v1/fine-tunes`

## Tests

- `go test ./sources/together_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
