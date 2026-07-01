# Cohere

Source Runtime SDK implementation for `cohere`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cohere`
- Health endpoint: `/source-runtimes/health?source_id=cohere`
- Source health receipt: `sources/cohere/source_health_receipt.json`
- EvidenceCAS reference kind: `cohere.evidence_cas_reference`

## Families

- `model_catalog`, emits `cohere.model_catalog`, reads `/v1/models`
- `connectors`, emits `cohere.connectors`, reads `/v1/connectors`
- `datasets`, emits `cohere.datasets`, reads `/v1/datasets`
- `fine_tuned_models`, emits `cohere.fine_tuned_models`, reads `/v1/finetuning/finetuned-models`

## Tests

- `go test ./sources/cohere -count=1`
