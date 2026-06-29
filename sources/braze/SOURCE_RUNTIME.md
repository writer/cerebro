# Braze

Generated Source Runtime SDK scaffold for `braze`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/braze`
- Health endpoint: `/source-runtimes/health?source_id=braze`
- Source health receipt: `sources/braze/source_health_receipt.json`
- EvidenceCAS reference kind: `braze.evidence_cas_reference`

## Families

- `users`, emits `braze.users`, reads `/v1/users`
- `accounts`, emits `braze.accounts`, reads `/v1/accounts`
- `records`, emits `braze.records`, reads `/v1/records`
- `policies`, emits `braze.policies`, reads `/v1/policies`
- `audit_events`, emits `braze.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/braze ./internal/sourceprojection -count=1`
- `make catalog-check`
