# Yardi Voyager

Generated Source Runtime SDK scaffold for `yardi_voyager`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/yardi_voyager`
- Health endpoint: `/source-runtimes/health?source_id=yardi_voyager`
- Source health receipt: `sources/yardi_voyager/source_health_receipt.json`
- EvidenceCAS reference kind: `yardi_voyager.evidence_cas_reference`

## Families

- `users`, emits `yardi_voyager.users`, reads `/v1/users`
- `accounts`, emits `yardi_voyager.accounts`, reads `/v1/accounts`
- `records`, emits `yardi_voyager.records`, reads `/v1/records`
- `policies`, emits `yardi_voyager.policies`, reads `/v1/policies`
- `audit_events`, emits `yardi_voyager.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/yardi_voyager ./internal/sourceprojection -count=1`
- `make catalog-check`
