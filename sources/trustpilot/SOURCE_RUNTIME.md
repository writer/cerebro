# Trustpilot

Generated Source Runtime SDK scaffold for `trustpilot`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/trustpilot`
- Health endpoint: `/source-runtimes/health?source_id=trustpilot`
- Source health receipt: `sources/trustpilot/source_health_receipt.json`
- EvidenceCAS reference kind: `trustpilot.evidence_cas_reference`

## Families

- `users`, emits `trustpilot.users`, reads `/v1/users`
- `accounts`, emits `trustpilot.accounts`, reads `/v1/accounts`
- `records`, emits `trustpilot.records`, reads `/v1/records`
- `policies`, emits `trustpilot.policies`, reads `/v1/policies`
- `audit_events`, emits `trustpilot.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/trustpilot ./internal/sourceprojection -count=1`
- `make catalog-check`
