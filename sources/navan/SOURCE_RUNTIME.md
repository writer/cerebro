# Navan

Generated Source Runtime SDK scaffold for `navan`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/navan`
- Health endpoint: `/source-runtimes/health?source_id=navan`
- Source health receipt: `sources/navan/source_health_receipt.json`
- EvidenceCAS reference kind: `navan.evidence_cas_reference`

## Families

- `users`, emits `navan.users`, reads `/v1/users`
- `accounts`, emits `navan.accounts`, reads `/v1/accounts`
- `records`, emits `navan.records`, reads `/v1/records`
- `policies`, emits `navan.policies`, reads `/v1/policies`
- `audit_events`, emits `navan.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/navan ./internal/sourceprojection -count=1`
- `make catalog-check`
