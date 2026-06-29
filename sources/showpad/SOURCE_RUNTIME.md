# Showpad

Generated Source Runtime SDK scaffold for `showpad`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/showpad`
- Health endpoint: `/source-runtimes/health?source_id=showpad`
- Source health receipt: `sources/showpad/source_health_receipt.json`
- EvidenceCAS reference kind: `showpad.evidence_cas_reference`

## Families

- `users`, emits `showpad.users`, reads `/v1/users`
- `accounts`, emits `showpad.accounts`, reads `/v1/accounts`
- `records`, emits `showpad.records`, reads `/v1/records`
- `policies`, emits `showpad.policies`, reads `/v1/policies`
- `audit_events`, emits `showpad.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/showpad ./internal/sourceprojection -count=1`
- `make catalog-check`
