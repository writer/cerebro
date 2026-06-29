# Productiv

Generated Source Runtime SDK scaffold for `productiv`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/productiv`
- Health endpoint: `/source-runtimes/health?source_id=productiv`
- Source health receipt: `sources/productiv/source_health_receipt.json`
- EvidenceCAS reference kind: `productiv.evidence_cas_reference`

## Families

- `users`, emits `productiv.users`, reads `/v1/users`
- `groups`, emits `productiv.groups`, reads `/v1/groups`
- `roles`, emits `productiv.roles`, reads `/v1/roles`
- `applications`, emits `productiv.applications`, reads `/v1/applications`
- `audit_events`, emits `productiv.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/productiv ./internal/sourceprojection -count=1`
- `make catalog-check`
