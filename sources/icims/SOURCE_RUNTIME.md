# Icims

Generated Source Runtime SDK scaffold for `icims`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/icims`
- Health endpoint: `/source-runtimes/health?source_id=icims`
- Source health receipt: `sources/icims/source_health_receipt.json`
- EvidenceCAS reference kind: `icims.evidence_cas_reference`

## Families

- `users`, emits `icims.users`, reads `/v1/users`
- `accounts`, emits `icims.accounts`, reads `/v1/accounts`
- `records`, emits `icims.records`, reads `/v1/records`
- `policies`, emits `icims.policies`, reads `/v1/policies`
- `audit_events`, emits `icims.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/icims ./internal/sourceprojection -count=1`
- `make catalog-check`
