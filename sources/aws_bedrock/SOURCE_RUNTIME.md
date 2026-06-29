# AWS Bedrock

Generated Source Runtime SDK scaffold for `aws_bedrock`.

## Runtime input

- Source type: `json_api`
- Auth model: `aws_sigv4`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/aws_bedrock`
- Health endpoint: `/source-runtimes/health?source_id=aws_bedrock`
- Source health receipt: `sources/aws_bedrock/source_health_receipt.json`
- EvidenceCAS reference kind: `aws_bedrock.evidence_cas_reference`

## Families

- `foundation_models`, emits `aws_bedrock.foundation_models`, reads `/foundation-models`
- `custom_models`, emits `aws_bedrock.custom_models`, reads `/custom-models`
- `provisioned_model_throughputs`, emits `aws_bedrock.provisioned_model_throughputs`, reads `/provisioned-model-throughputs`
- `model_customization_jobs`, emits `aws_bedrock.model_customization_jobs`, reads `/model-customization-jobs`
- `guardrails`, emits `aws_bedrock.guardrails`, reads `/guardrails`

## Tests

- `go test ./sources/aws_bedrock ./internal/sourceprojection -count=1`
- `make catalog-check`
