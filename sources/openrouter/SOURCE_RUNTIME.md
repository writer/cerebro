# OpenRouter

Source Runtime SDK implementation for `openrouter`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/openrouter`
- Health endpoint: `/source-runtimes/health?source_id=openrouter`
- Source health receipt: `sources/openrouter/source_health_receipt.json`
- EvidenceCAS reference kind: `openrouter.evidence_cas_reference`

## Families

- `organization_members`, emits `openrouter.organization_members`, reads `/v1/organization/members`
- `api_keys`, emits `openrouter.api_keys`, reads `/v1/keys`
- `provider_keys`, emits `openrouter.provider_keys`, reads `/v1/byok`
- `usage_reports`, emits `openrouter.usage_reports`, reads `/v1/activity`

## Tests

- `go test ./sources/openrouter -count=1`
