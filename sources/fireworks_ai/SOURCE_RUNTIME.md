# Fireworks AI

Generated Source Runtime SDK scaffold for `fireworks_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fireworks_ai`
- Health endpoint: `/source-runtimes/health?source_id=fireworks_ai`
- Source health receipt: `sources/fireworks_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `fireworks_ai.evidence_cas_reference`

## Families

- `model_deployments`, emits `fireworks_ai.model_deployments`, reads `/v1/accounts/${config.account_id}/deployments`
- `service_accounts`, emits `fireworks_ai.service_accounts`, reads `/v1/accounts/${config.account_id}/serviceAccounts`
- `audit_logs`, emits `fireworks_ai.audit_logs`, reads `/v1/accounts/${config.account_id}/auditLogs`
- `billing_metrics`, emits `fireworks_ai.billing_metrics`, reads `/v1/accounts/${config.account_id}/billing/metrics`

## Tests

- `go test ./sources/fireworks_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
