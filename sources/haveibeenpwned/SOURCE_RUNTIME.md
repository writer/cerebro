# Have I Been Pwned

Generated Source Runtime SDK scaffold for `haveibeenpwned`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/haveibeenpwned`
- Health endpoint: `/source-runtimes/health?source_id=haveibeenpwned`
- Source health receipt: `sources/haveibeenpwned/source_health_receipt.json`
- EvidenceCAS reference kind: `haveibeenpwned.evidence_cas_reference`

## Families

- `breaches`, emits `haveibeenpwned.breaches`, reads `/breaches`
- `affected_accounts`, emits `haveibeenpwned.affected_accounts`, reads `/breachedaccount`
- `audit_events`, emits `haveibeenpwned.audit_events`, reads `/audit-events`

## Tests

- `go test ./sources/haveibeenpwned ./internal/sourceprojection -count=1`
- `make catalog-check`
