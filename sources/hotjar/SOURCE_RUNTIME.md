# Hotjar

Generated Source Runtime SDK scaffold for `hotjar`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hotjar`
- Health endpoint: `/source-runtimes/health?source_id=hotjar`
- Source health receipt: `sources/hotjar/source_health_receipt.json`
- EvidenceCAS reference kind: `hotjar.evidence_cas_reference`

## Families

- `users`, emits `hotjar.users`, reads `/v1/users`
- `accounts`, emits `hotjar.accounts`, reads `/v1/accounts`
- `records`, emits `hotjar.records`, reads `/v1/records`
- `policies`, emits `hotjar.policies`, reads `/v1/policies`
- `audit_events`, emits `hotjar.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hotjar ./internal/sourceprojection -count=1`
- `make catalog-check`
