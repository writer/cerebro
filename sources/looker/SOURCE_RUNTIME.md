# Looker

Generated Source Runtime SDK scaffold for `looker`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/looker`
- Health endpoint: `/source-runtimes/health?source_id=looker`
- Source health receipt: `sources/looker/source_health_receipt.json`
- EvidenceCAS reference kind: `looker.evidence_cas_reference`

## Families

- `users`, emits `looker.users`, reads `/v1/users`
- `accounts`, emits `looker.accounts`, reads `/v1/accounts`
- `records`, emits `looker.records`, reads `/v1/records`
- `policies`, emits `looker.policies`, reads `/v1/policies`
- `audit_events`, emits `looker.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/looker ./internal/sourceprojection -count=1`
- `make catalog-check`
