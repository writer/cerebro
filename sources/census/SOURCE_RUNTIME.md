# Census

Generated Source Runtime SDK scaffold for `census`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/census`
- Health endpoint: `/source-runtimes/health?source_id=census`
- Source health receipt: `sources/census/source_health_receipt.json`
- EvidenceCAS reference kind: `census.evidence_cas_reference`

## Families

- `users`, emits `census.users`, reads `/v1/users`
- `accounts`, emits `census.accounts`, reads `/v1/accounts`
- `records`, emits `census.records`, reads `/v1/records`
- `policies`, emits `census.policies`, reads `/v1/policies`
- `audit_events`, emits `census.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/census ./internal/sourceprojection -count=1`
- `make catalog-check`
