# Linksquares

Generated Source Runtime SDK scaffold for `linksquares`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/linksquares`
- Health endpoint: `/source-runtimes/health?source_id=linksquares`
- Source health receipt: `sources/linksquares/source_health_receipt.json`
- EvidenceCAS reference kind: `linksquares.evidence_cas_reference`

## Families

- `users`, emits `linksquares.users`, reads `/v1/users`
- `accounts`, emits `linksquares.accounts`, reads `/v1/accounts`
- `records`, emits `linksquares.records`, reads `/v1/records`
- `policies`, emits `linksquares.policies`, reads `/v1/policies`
- `audit_events`, emits `linksquares.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/linksquares ./internal/sourceprojection -count=1`
- `make catalog-check`
