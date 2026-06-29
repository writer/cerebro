# Docebo

Generated Source Runtime SDK scaffold for `docebo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/docebo`
- Health endpoint: `/source-runtimes/health?source_id=docebo`
- Source health receipt: `sources/docebo/source_health_receipt.json`
- EvidenceCAS reference kind: `docebo.evidence_cas_reference`

## Families

- `users`, emits `docebo.users`, reads `/v1/users`
- `accounts`, emits `docebo.accounts`, reads `/v1/accounts`
- `records`, emits `docebo.records`, reads `/v1/records`
- `policies`, emits `docebo.policies`, reads `/v1/policies`
- `audit_events`, emits `docebo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/docebo ./internal/sourceprojection -count=1`
- `make catalog-check`
