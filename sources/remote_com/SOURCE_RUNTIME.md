# Remote.com

Generated Source Runtime SDK scaffold for `remote_com`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/remote_com`
- Health endpoint: `/source-runtimes/health?source_id=remote_com`
- Source health receipt: `sources/remote_com/source_health_receipt.json`
- EvidenceCAS reference kind: `remote_com.evidence_cas_reference`

## Families

- `users`, emits `remote_com.users`, reads `/v1/users`
- `accounts`, emits `remote_com.accounts`, reads `/v1/accounts`
- `records`, emits `remote_com.records`, reads `/v1/records`
- `policies`, emits `remote_com.policies`, reads `/v1/policies`
- `audit_events`, emits `remote_com.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/remote_com ./internal/sourceprojection -count=1`
- `make catalog-check`
