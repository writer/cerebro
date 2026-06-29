# Brightflag

Generated Source Runtime SDK scaffold for `brightflag`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/brightflag`
- Health endpoint: `/source-runtimes/health?source_id=brightflag`
- Source health receipt: `sources/brightflag/source_health_receipt.json`
- EvidenceCAS reference kind: `brightflag.evidence_cas_reference`

## Families

- `users`, emits `brightflag.users`, reads `/v1/users`
- `accounts`, emits `brightflag.accounts`, reads `/v1/accounts`
- `records`, emits `brightflag.records`, reads `/v1/records`
- `policies`, emits `brightflag.policies`, reads `/v1/policies`
- `audit_events`, emits `brightflag.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/brightflag ./internal/sourceprojection -count=1`
- `make catalog-check`
