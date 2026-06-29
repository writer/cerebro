# Hugging Face

Generated Source Runtime SDK scaffold for `huggingface`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/huggingface`
- Health endpoint: `/source-runtimes/health?source_id=huggingface`
- Source health receipt: `sources/huggingface/source_health_receipt.json`
- EvidenceCAS reference kind: `huggingface.evidence_cas_reference`

## Families

- `organization_members`, emits `huggingface.organization_members`, reads `/organizations/${config.organization}/members`
- `resource_groups`, emits `huggingface.resource_groups`, reads `/organizations/${config.organization}/resource-groups`
- `audit_logs`, emits `huggingface.audit_logs`, reads `/organizations/${config.organization}/audit-logs`
- `repositories`, emits `huggingface.repositories`, reads `/models`

## Tests

- `go test ./sources/huggingface ./internal/sourceprojection -count=1`
- `make catalog-check`
