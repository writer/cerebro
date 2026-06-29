# Google Gemini

Generated Source Runtime SDK scaffold for `google_gemini`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/google_gemini`
- Health endpoint: `/source-runtimes/health?source_id=google_gemini`
- Source health receipt: `sources/google_gemini/source_health_receipt.json`
- EvidenceCAS reference kind: `google_gemini.evidence_cas_reference`

## Families

- `model_catalog`, emits `google_gemini.model_catalog`, reads `/v1beta/models`
- `tuned_models`, emits `google_gemini.tuned_models`, reads `/v1beta/tunedModels`
- `files`, emits `google_gemini.files`, reads `/v1beta/files`
- `cached_contents`, emits `google_gemini.cached_contents`, reads `/v1beta/cachedContents`
- `batch_jobs`, emits `google_gemini.batch_jobs`, reads `/v1beta/batches`

## Tests

- `go test ./sources/google_gemini ./internal/sourceprojection -count=1`
- `make catalog-check`
