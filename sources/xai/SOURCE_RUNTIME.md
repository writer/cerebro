# xAI

Generated Source Runtime SDK scaffold for `xai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/xai`
- Health endpoint: `/source-runtimes/health?source_id=xai`
- Source health receipt: `sources/xai/source_health_receipt.json`
- EvidenceCAS reference kind: `xai.evidence_cas_reference`

## Families

- `api_keys`, emits `xai.api_keys`, reads `/management/api-keys`
- `audit_logs`, emits `xai.audit_logs`, reads `/management/audit-logs`
- `usage_reports`, emits `xai.usage_reports`, reads `/management/usage`
- `model_access`, emits `xai.model_access`, reads `/management/model-access`

## Tests

- `go test ./sources/xai ./internal/sourceprojection -count=1`
- `make catalog-check`
