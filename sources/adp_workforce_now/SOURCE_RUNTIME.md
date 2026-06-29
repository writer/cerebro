# ADP Workforce Now

Generated Source Runtime SDK scaffold for `adp_workforce_now`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/adp_workforce_now`
- Health endpoint: `/source-runtimes/health?source_id=adp_workforce_now`
- Source health receipt: `sources/adp_workforce_now/source_health_receipt.json`
- EvidenceCAS reference kind: `adp_workforce_now.evidence_cas_reference`

## Families

- `users`, emits `adp_workforce_now.users`, reads `/v1/users`
- `accounts`, emits `adp_workforce_now.accounts`, reads `/v1/accounts`
- `records`, emits `adp_workforce_now.records`, reads `/v1/records`
- `policies`, emits `adp_workforce_now.policies`, reads `/v1/policies`
- `audit_events`, emits `adp_workforce_now.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/adp_workforce_now ./internal/sourceprojection -count=1`
- `make catalog-check`
