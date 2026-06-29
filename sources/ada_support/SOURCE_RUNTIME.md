# Ada Support

Generated Source Runtime SDK scaffold for `ada_support`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ada_support`
- Health endpoint: `/source-runtimes/health?source_id=ada_support`
- Source health receipt: `sources/ada_support/source_health_receipt.json`
- EvidenceCAS reference kind: `ada_support.evidence_cas_reference`

## Families

- `users`, emits `ada_support.users`, reads `/v1/users`
- `accounts`, emits `ada_support.accounts`, reads `/v1/accounts`
- `records`, emits `ada_support.records`, reads `/v1/records`
- `policies`, emits `ada_support.policies`, reads `/v1/policies`
- `audit_events`, emits `ada_support.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/ada_support ./internal/sourceprojection -count=1`
- `make catalog-check`
