# Coupa

Generated Source Runtime SDK scaffold for `coupa`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/coupa`
- Health endpoint: `/source-runtimes/health?source_id=coupa`
- Source health receipt: `sources/coupa/source_health_receipt.json`
- EvidenceCAS reference kind: `coupa.evidence_cas_reference`

## Families

- `users`, emits `coupa.users`, reads `/v1/users`
- `accounts`, emits `coupa.accounts`, reads `/v1/accounts`
- `records`, emits `coupa.records`, reads `/v1/records`
- `policies`, emits `coupa.policies`, reads `/v1/policies`
- `audit_events`, emits `coupa.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/coupa ./internal/sourceprojection -count=1`
- `make catalog-check`
