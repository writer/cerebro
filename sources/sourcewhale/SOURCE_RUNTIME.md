# Sourcewhale

Generated Source Runtime SDK scaffold for `sourcewhale`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sourcewhale`
- Health endpoint: `/source-runtimes/health?source_id=sourcewhale`
- Source health receipt: `sources/sourcewhale/source_health_receipt.json`
- EvidenceCAS reference kind: `sourcewhale.evidence_cas_reference`

## Families

- `users`, emits `sourcewhale.users`, reads `/v1/users`
- `accounts`, emits `sourcewhale.accounts`, reads `/v1/accounts`
- `records`, emits `sourcewhale.records`, reads `/v1/records`
- `policies`, emits `sourcewhale.policies`, reads `/v1/policies`
- `audit_events`, emits `sourcewhale.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sourcewhale ./internal/sourceprojection -count=1`
- `make catalog-check`
