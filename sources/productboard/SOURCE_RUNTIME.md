# Productboard

Generated Source Runtime SDK scaffold for `productboard`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/productboard`
- Health endpoint: `/source-runtimes/health?source_id=productboard`
- Source health receipt: `sources/productboard/source_health_receipt.json`
- EvidenceCAS reference kind: `productboard.evidence_cas_reference`

## Families

- `users`, emits `productboard.users`, reads `/v1/users`
- `projects`, emits `productboard.projects`, reads `/v1/projects`
- `repositories`, emits `productboard.repositories`, reads `/v1/repositories`
- `deployments`, emits `productboard.deployments`, reads `/v1/deployments`
- `audit_events`, emits `productboard.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/productboard ./internal/sourceprojection -count=1`
- `make catalog-check`
