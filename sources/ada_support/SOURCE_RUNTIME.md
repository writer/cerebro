# Ada Support

Provider-verified Source Runtime SDK mapping for `ada_support`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token` (`Authorization: Bearer <token>`)
- Base URL: Ada tenant API base URL such as `https://example.ada.support/api`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ada_support`
- Health endpoint: `/source-runtimes/health?source_id=ada_support`
- Source health receipt: `sources/ada_support/source_health_receipt.json`
- EvidenceCAS reference kind: `ada_support.evidence_cas_reference`

## Families

- `end_users`, emits `ada_support.end_users`, reads `GET /v2/end-users/`
- `platform_integrations`, emits `ada_support.platform_integrations`, reads `GET /v2/platform-integrations/`
- `conversations`, emits `ada_support.conversations`, reads `GET /v2/export/conversations`
- `knowledge_articles`, emits `ada_support.knowledge_articles`, reads `GET /v2/knowledge/articles/`
- `audit_events`, emits `ada_support.audit_events`, reads `GET /v2/analytics/audit-log/events/`

## Tests

- `go test ./sources/ada_support ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/ada_support/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
