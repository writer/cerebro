# Salesforce

Generated Source Runtime SDK scaffold for `salesforce`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/salesforce`
- Health endpoint: `/source-runtimes/health?source_id=salesforce`
- Source health receipt: `sources/salesforce/source_health_receipt.json`
- EvidenceCAS reference kind: `salesforce.evidence_cas_reference`

## Families

- `users`, emits `salesforce.users`, reads `/v1/users`
- `assets`, emits `salesforce.assets`, reads `/v1/records`
- `audit_events`, emits `salesforce.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/salesforce ./internal/sourceprojection -count=1`
- `make catalog-check`
