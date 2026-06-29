# Cloudtalk

Generated Source Runtime SDK scaffold for `cloudtalk`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cloudtalk`
- Health endpoint: `/source-runtimes/health?source_id=cloudtalk`
- Source health receipt: `sources/cloudtalk/source_health_receipt.json`
- EvidenceCAS reference kind: `cloudtalk.evidence_cas_reference`

## Families

- `users`, emits `cloudtalk.users`, reads `/v1/users`
- `accounts`, emits `cloudtalk.accounts`, reads `/v1/accounts`
- `records`, emits `cloudtalk.records`, reads `/v1/records`
- `policies`, emits `cloudtalk.policies`, reads `/v1/policies`
- `audit_events`, emits `cloudtalk.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cloudtalk ./internal/sourceprojection -count=1`
- `make catalog-check`
