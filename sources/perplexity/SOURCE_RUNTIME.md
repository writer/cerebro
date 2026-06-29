# Perplexity

Generated Source Runtime SDK scaffold for `perplexity`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/perplexity`
- Health endpoint: `/source-runtimes/health?source_id=perplexity`
- Source health receipt: `sources/perplexity/source_health_receipt.json`
- EvidenceCAS reference kind: `perplexity.evidence_cas_reference`

## Families

- `api_groups`, emits `perplexity.api_groups`, reads `/api-groups`
- `api_keys`, emits `perplexity.api_keys`, reads `/api-keys`
- `team_members`, emits `perplexity.team_members`, reads `/team/members`
- `usage_reports`, emits `perplexity.usage_reports`, reads `/usage`

## Tests

- `go test ./sources/perplexity ./internal/sourceprojection -count=1`
- `make catalog-check`
