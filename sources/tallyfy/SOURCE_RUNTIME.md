# Tallyfy

Generated Source Runtime SDK scaffold for `tallyfy`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/tallyfy`
- Health endpoint: `/source-runtimes/health?source_id=tallyfy`
- Source health receipt: `sources/tallyfy/source_health_receipt.json`
- EvidenceCAS reference kind: `tallyfy.evidence_cas_reference`

## Families

- `users`, emits `tallyfy.users`, reads `/v1/users`
- `accounts`, emits `tallyfy.accounts`, reads `/v1/accounts`
- `records`, emits `tallyfy.records`, reads `/v1/records`
- `policies`, emits `tallyfy.policies`, reads `/v1/policies`
- `audit_events`, emits `tallyfy.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/tallyfy ./internal/sourceprojection -count=1`
- `make catalog-check`
