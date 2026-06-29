# Performyard

Generated Source Runtime SDK scaffold for `performyard`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/performyard`
- Health endpoint: `/source-runtimes/health?source_id=performyard`
- Source health receipt: `sources/performyard/source_health_receipt.json`
- EvidenceCAS reference kind: `performyard.evidence_cas_reference`

## Families

- `users`, emits `performyard.users`, reads `/v1/users`
- `accounts`, emits `performyard.accounts`, reads `/v1/accounts`
- `records`, emits `performyard.records`, reads `/v1/records`
- `policies`, emits `performyard.policies`, reads `/v1/policies`
- `audit_events`, emits `performyard.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/performyard ./internal/sourceprojection -count=1`
- `make catalog-check`
