# Snowflake

Generated Source Runtime SDK scaffold for `snowflake`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/snowflake`
- Health endpoint: `/source-runtimes/health?source_id=snowflake`
- Source health receipt: `sources/snowflake/source_health_receipt.json`
- EvidenceCAS reference kind: `snowflake.evidence_cas_reference`

## Families

- `assets`, emits `snowflake.assets`, reads `/v1/assets`
- `cortex_search_services`, emits `snowflake.cortex_search_services`, reads `/v1/cortex/search/services`
- `audit_events`, emits `snowflake.audit_events`, reads `/v1/audit/events`
- `vulnerabilities`, emits `snowflake.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/snowflake ./internal/sourceprojection -count=1`
- `make catalog-check`
