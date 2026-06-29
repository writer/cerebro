# LastPass Business

Generated Source Runtime SDK scaffold for `lastpass_business`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/lastpass_business`
- Health endpoint: `/source-runtimes/health?source_id=lastpass_business`
- Source health receipt: `sources/lastpass_business/source_health_receipt.json`
- EvidenceCAS reference kind: `lastpass_business.evidence_cas_reference`

## Families

- `users`, emits `lastpass_business.users`, reads `/v1/users`
- `secrets`, emits `lastpass_business.secrets`, reads `/v1/secrets`
- `audit_events`, emits `lastpass_business.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/lastpass_business ./internal/sourceprojection -count=1`
- `make catalog-check`
