# Groq

Generated Source Runtime SDK scaffold for `groq`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/groq`
- Health endpoint: `/source-runtimes/health?source_id=groq`
- Source health receipt: `sources/groq/source_health_receipt.json`
- EvidenceCAS reference kind: `groq.evidence_cas_reference`

## Families

- `model_catalog`, emits `groq.model_catalog`, reads `/models`
- `files`, emits `groq.files`, reads `/files`
- `batch_jobs`, emits `groq.batch_jobs`, reads `/batches`
- `fine_tuning_jobs`, emits `groq.fine_tuning_jobs`, reads `/fine_tuning/jobs`

## Tests

- `go test ./sources/groq ./internal/sourceprojection -count=1`
- `make catalog-check`
