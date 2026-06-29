# Nice Cxone

Generated Source Runtime SDK scaffold for `nice_cxone`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/nice_cxone`
- Health endpoint: `/source-runtimes/health?source_id=nice_cxone`
- Source health receipt: `sources/nice_cxone/source_health_receipt.json`
- EvidenceCAS reference kind: `nice_cxone.evidence_cas_reference`

## Families

- `users`, emits `nice_cxone.users`, reads `/v1/users`
- `accounts`, emits `nice_cxone.accounts`, reads `/v1/accounts`
- `records`, emits `nice_cxone.records`, reads `/v1/records`
- `policies`, emits `nice_cxone.policies`, reads `/v1/policies`
- `audit_events`, emits `nice_cxone.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/nice_cxone ./internal/sourceprojection -count=1`
- `make catalog-check`
