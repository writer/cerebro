# Cloudflare Workers AI

Generated Source Runtime SDK scaffold for `cloudflare_workers_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cloudflare_workers_ai`
- Health endpoint: `/source-runtimes/health?source_id=cloudflare_workers_ai`
- Source health receipt: `sources/cloudflare_workers_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `cloudflare_workers_ai.evidence_cas_reference`

## Families

- `model_catalog`, emits `cloudflare_workers_ai.model_catalog`, reads `/accounts/${config.account_id}/ai/models/search`
- `ai_gateways`, emits `cloudflare_workers_ai.ai_gateways`, reads `/accounts/${config.account_id}/ai-gateway/gateways`
- `gateway_provider_configs`, emits `cloudflare_workers_ai.gateway_provider_configs`, reads `/accounts/${config.account_id}/ai-gateway/gateways/${config.gateway_id}/provider_configs`
- `gateway_evaluations`, emits `cloudflare_workers_ai.gateway_evaluations`, reads `/accounts/${config.account_id}/ai-gateway/gateways/${config.gateway_id}/evaluations`
- `gateway_logs`, emits `cloudflare_workers_ai.gateway_logs`, reads `/accounts/${config.account_id}/ai-gateway/gateways/${config.gateway_id}/logs`
- `vectorize_indexes`, emits `cloudflare_workers_ai.vectorize_indexes`, reads `/accounts/${config.account_id}/vectorize/v2/indexes`

## Tests

- `go test ./sources/cloudflare_workers_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
