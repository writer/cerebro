# Metaplane

Generated Source Runtime SDK scaffold for `metaplane`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/metaplane`
- Health endpoint: `/source-runtimes/health?source_id=metaplane`
- Source health receipt: `sources/metaplane/source_health_receipt.json`
- EvidenceCAS reference kind: `metaplane.evidence_cas_reference`

## Families

- `users`, emits `metaplane.users`, reads `/v1/users`
- `accounts`, emits `metaplane.accounts`, reads `/v1/accounts`
- `records`, emits `metaplane.records`, reads `/v1/records`
- `policies`, emits `metaplane.policies`, reads `/v1/policies`
- `audit_events`, emits `metaplane.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/metaplane ./internal/sourceprojection -count=1`
- `make catalog-check`
