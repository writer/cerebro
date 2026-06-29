# Quickbooks Online

Generated Source Runtime SDK scaffold for `quickbooks_online`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/quickbooks_online`
- Health endpoint: `/source-runtimes/health?source_id=quickbooks_online`
- Source health receipt: `sources/quickbooks_online/source_health_receipt.json`
- EvidenceCAS reference kind: `quickbooks_online.evidence_cas_reference`

## Families

- `users`, emits `quickbooks_online.users`, reads `/v1/users`
- `accounts`, emits `quickbooks_online.accounts`, reads `/v1/accounts`
- `records`, emits `quickbooks_online.records`, reads `/v1/records`
- `policies`, emits `quickbooks_online.policies`, reads `/v1/policies`
- `audit_events`, emits `quickbooks_online.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/quickbooks_online ./internal/sourceprojection -count=1`
- `make catalog-check`
