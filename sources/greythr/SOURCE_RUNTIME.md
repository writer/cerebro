# Greythr

Generated Source Runtime SDK scaffold for `greythr`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/greythr`
- Health endpoint: `/source-runtimes/health?source_id=greythr`
- Source health receipt: `sources/greythr/source_health_receipt.json`
- EvidenceCAS reference kind: `greythr.evidence_cas_reference`

## Families

- `users`, emits `greythr.users`, reads `/v1/users`
- `accounts`, emits `greythr.accounts`, reads `/v1/accounts`
- `records`, emits `greythr.records`, reads `/v1/records`
- `policies`, emits `greythr.policies`, reads `/v1/policies`
- `audit_events`, emits `greythr.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/greythr ./internal/sourceprojection -count=1`
- `make catalog-check`
