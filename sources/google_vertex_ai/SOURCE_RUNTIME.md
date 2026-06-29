# Google Vertex AI

Generated Source Runtime SDK scaffold for `google_vertex_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/google_vertex_ai`
- Health endpoint: `/source-runtimes/health?source_id=google_vertex_ai`
- Source health receipt: `sources/google_vertex_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `google_vertex_ai.evidence_cas_reference`

## Families

- `models`, emits `google_vertex_ai.models`, reads `/v1/projects/${config.project_id}/locations/${config.location}/models`
- `endpoints`, emits `google_vertex_ai.endpoints`, reads `/v1/projects/${config.project_id}/locations/${config.location}/endpoints`
- `custom_jobs`, emits `google_vertex_ai.custom_jobs`, reads `/v1/projects/${config.project_id}/locations/${config.location}/customJobs`
- `batch_prediction_jobs`, emits `google_vertex_ai.batch_prediction_jobs`, reads `/v1/projects/${config.project_id}/locations/${config.location}/batchPredictionJobs`
- `indexes`, emits `google_vertex_ai.indexes`, reads `/v1/projects/${config.project_id}/locations/${config.location}/indexes`
- `reasoning_engines`, emits `google_vertex_ai.reasoning_engines`, reads `/v1/projects/${config.project_id}/locations/${config.location}/reasoningEngines`

## Tests

- `go test ./sources/google_vertex_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
