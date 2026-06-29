# Ironclad

Generated Source Runtime SDK scaffold for `ironclad`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ironclad`
- Health endpoint: `/source-runtimes/health?source_id=ironclad`
- Source health receipt: `sources/ironclad/source_health_receipt.json`
- EvidenceCAS reference kind: `ironclad.evidence_cas_reference`

## Families

- `users`, emits `ironclad.users`, reads `/v1/users`
- `accounts`, emits `ironclad.accounts`, reads `/v1/accounts`
- `records`, emits `ironclad.records`, reads `/v1/records`
- `policies`, emits `ironclad.policies`, reads `/v1/policies`
- `audit_events`, emits `ironclad.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/ironclad ./internal/sourceprojection -count=1`
- `make catalog-check`
