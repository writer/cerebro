# Qualtrics

Generated Source Runtime SDK scaffold for `qualtrics`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/qualtrics`
- Health endpoint: `/source-runtimes/health?source_id=qualtrics`
- Source health receipt: `sources/qualtrics/source_health_receipt.json`
- EvidenceCAS reference kind: `qualtrics.evidence_cas_reference`

## Families

- `users`, emits `qualtrics.users`, reads `/v1/users`
- `accounts`, emits `qualtrics.accounts`, reads `/v1/accounts`
- `records`, emits `qualtrics.records`, reads `/v1/records`
- `policies`, emits `qualtrics.policies`, reads `/v1/policies`
- `audit_events`, emits `qualtrics.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/qualtrics ./internal/sourceprojection -count=1`
- `make catalog-check`
