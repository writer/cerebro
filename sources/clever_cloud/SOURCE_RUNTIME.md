# Clever Cloud

Generated Source Runtime SDK scaffold for `clever_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/clever_cloud`
- Health endpoint: `/source-runtimes/health?source_id=clever_cloud`
- Source health receipt: `sources/clever_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `clever_cloud.evidence_cas_reference`

## Families

- `email`, emits `clever_cloud.email`, reads `/github/emails`
- `token`, emits `clever_cloud.token`, reads `/self/tokens`
- `networkgroup`, emits `clever_cloud.networkgroup`, reads `/v4/networkgroups/organisations/${config.ownerid}/networkgroups`
- `deployment`, emits `clever_cloud.deployment`, reads `/organisations/${config.id}/deployments`

## Tests

- `go test ./sources/clever_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
