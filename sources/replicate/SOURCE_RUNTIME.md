# Replicate

Generated Source Runtime SDK scaffold for `replicate`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/replicate`
- Health endpoint: `/source-runtimes/health?source_id=replicate`
- Source health receipt: `sources/replicate/source_health_receipt.json`
- EvidenceCAS reference kind: `replicate.evidence_cas_reference`

## Families

- `models`, emits `replicate.models`, reads `/v1/models`
- `deployments`, emits `replicate.deployments`, reads `/v1/deployments`
- `collections`, emits `replicate.collections`, reads `/v1/collections`
- `predictions`, emits `replicate.predictions`, reads `/v1/predictions`

## Tests

- `go test ./sources/replicate ./internal/sourceprojection -count=1`
- `make catalog-check`
