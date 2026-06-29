# Surveymonkey

Generated Source Runtime SDK scaffold for `surveymonkey`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/surveymonkey`
- Health endpoint: `/source-runtimes/health?source_id=surveymonkey`
- Source health receipt: `sources/surveymonkey/source_health_receipt.json`
- EvidenceCAS reference kind: `surveymonkey.evidence_cas_reference`

## Families

- `users`, emits `surveymonkey.users`, reads `/v1/users`
- `accounts`, emits `surveymonkey.accounts`, reads `/v1/accounts`
- `records`, emits `surveymonkey.records`, reads `/v1/records`
- `policies`, emits `surveymonkey.policies`, reads `/v1/policies`
- `audit_events`, emits `surveymonkey.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/surveymonkey ./internal/sourceprojection -count=1`
- `make catalog-check`
