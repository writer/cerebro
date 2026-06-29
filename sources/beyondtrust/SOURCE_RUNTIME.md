# BeyondTrust

Generated Source Runtime SDK scaffold for `beyondtrust`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/beyondtrust`
- Health endpoint: `/source-runtimes/health?source_id=beyondtrust`
- Source health receipt: `sources/beyondtrust/source_health_receipt.json`
- EvidenceCAS reference kind: `beyondtrust.evidence_cas_reference`

## Families

- `users`, emits `beyondtrust.users`, reads `/v1/users`
- `secrets`, emits `beyondtrust.secrets`, reads `/v1/secrets`
- `audit_events`, emits `beyondtrust.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/beyondtrust ./internal/sourceprojection -count=1`
- `make catalog-check`
