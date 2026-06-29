# Bazaarvoice

Generated Source Runtime SDK scaffold for `bazaarvoice`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bazaarvoice`
- Health endpoint: `/source-runtimes/health?source_id=bazaarvoice`
- Source health receipt: `sources/bazaarvoice/source_health_receipt.json`
- EvidenceCAS reference kind: `bazaarvoice.evidence_cas_reference`

## Families

- `users`, emits `bazaarvoice.users`, reads `/v1/users`
- `accounts`, emits `bazaarvoice.accounts`, reads `/v1/accounts`
- `records`, emits `bazaarvoice.records`, reads `/v1/records`
- `policies`, emits `bazaarvoice.policies`, reads `/v1/policies`
- `audit_events`, emits `bazaarvoice.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/bazaarvoice ./internal/sourceprojection -count=1`
- `make catalog-check`
