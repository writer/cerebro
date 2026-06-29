# Personio

Generated Source Runtime SDK scaffold for `personio`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/personio`
- Health endpoint: `/source-runtimes/health?source_id=personio`
- Source health receipt: `sources/personio/source_health_receipt.json`
- EvidenceCAS reference kind: `personio.evidence_cas_reference`

## Families

- `users`, emits `personio.users`, reads `/v1/users`
- `accounts`, emits `personio.accounts`, reads `/v1/accounts`
- `records`, emits `personio.records`, reads `/v1/records`
- `policies`, emits `personio.policies`, reads `/v1/policies`
- `audit_events`, emits `personio.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/personio ./internal/sourceprojection -count=1`
- `make catalog-check`
