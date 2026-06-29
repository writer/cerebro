# Ziphq

Generated Source Runtime SDK scaffold for `ziphq`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ziphq`
- Health endpoint: `/source-runtimes/health?source_id=ziphq`
- Source health receipt: `sources/ziphq/source_health_receipt.json`
- EvidenceCAS reference kind: `ziphq.evidence_cas_reference`

## Families

- `users`, emits `ziphq.users`, reads `/v1/users`
- `accounts`, emits `ziphq.accounts`, reads `/v1/accounts`
- `records`, emits `ziphq.records`, reads `/v1/records`
- `policies`, emits `ziphq.policies`, reads `/v1/policies`
- `audit_events`, emits `ziphq.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/ziphq ./internal/sourceprojection -count=1`
- `make catalog-check`
