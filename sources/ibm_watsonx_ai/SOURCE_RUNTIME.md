# IBM watsonx.ai

Generated Source Runtime SDK scaffold for `ibm_watsonx_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ibm_watsonx_ai`
- Health endpoint: `/source-runtimes/health?source_id=ibm_watsonx_ai`
- Source health receipt: `sources/ibm_watsonx_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `ibm_watsonx_ai.evidence_cas_reference`

## Families

- `foundation_model_specs`, emits `ibm_watsonx_ai.foundation_model_specs`, reads `/ml/v1/foundation_model_specs`
- `foundation_model_tasks`, emits `ibm_watsonx_ai.foundation_model_tasks`, reads `/ml/v1/foundation_model_tasks`
- `custom_models`, emits `ibm_watsonx_ai.custom_models`, reads `/ml/v4/models`
- `deployments`, emits `ibm_watsonx_ai.deployments`, reads `/ml/v4/deployments`
- `training_jobs`, emits `ibm_watsonx_ai.training_jobs`, reads `/ml/v4/trainings`

## Tests

- `go test ./sources/ibm_watsonx_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
