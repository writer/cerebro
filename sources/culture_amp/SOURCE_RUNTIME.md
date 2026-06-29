# Culture Amp

Generated Source Runtime SDK scaffold for `culture_amp`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/culture_amp`
- Health endpoint: `/source-runtimes/health?source_id=culture_amp`
- Source health receipt: `sources/culture_amp/source_health_receipt.json`
- EvidenceCAS reference kind: `culture_amp.evidence_cas_reference`

## Families

- `users`, emits `culture_amp.users`, reads `/v1/users`
- `accounts`, emits `culture_amp.accounts`, reads `/v1/accounts`
- `records`, emits `culture_amp.records`, reads `/v1/records`
- `policies`, emits `culture_amp.policies`, reads `/v1/policies`
- `audit_events`, emits `culture_amp.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/culture_amp ./internal/sourceprojection -count=1`
- `make catalog-check`
