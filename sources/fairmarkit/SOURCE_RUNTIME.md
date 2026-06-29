# Fairmarkit

Generated Source Runtime SDK scaffold for `fairmarkit`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fairmarkit`
- Health endpoint: `/source-runtimes/health?source_id=fairmarkit`
- Source health receipt: `sources/fairmarkit/source_health_receipt.json`
- EvidenceCAS reference kind: `fairmarkit.evidence_cas_reference`

## Families

- `users`, emits `fairmarkit.users`, reads `/v1/users`
- `accounts`, emits `fairmarkit.accounts`, reads `/v1/accounts`
- `records`, emits `fairmarkit.records`, reads `/v1/records`
- `policies`, emits `fairmarkit.policies`, reads `/v1/policies`
- `audit_events`, emits `fairmarkit.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/fairmarkit ./internal/sourceprojection -count=1`
- `make catalog-check`
