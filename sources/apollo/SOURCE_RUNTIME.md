# Apollo

Generated Source Runtime SDK scaffold for `apollo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/apollo`
- Health endpoint: `/source-runtimes/health?source_id=apollo`
- Source health receipt: `sources/apollo/source_health_receipt.json`
- EvidenceCAS reference kind: `apollo.evidence_cas_reference`

## Families

- `users`, emits `apollo.users`, reads `/v1/users`
- `accounts`, emits `apollo.accounts`, reads `/v1/accounts`
- `records`, emits `apollo.records`, reads `/v1/records`
- `policies`, emits `apollo.policies`, reads `/v1/policies`
- `audit_events`, emits `apollo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/apollo ./internal/sourceprojection -count=1`
- `make catalog-check`
