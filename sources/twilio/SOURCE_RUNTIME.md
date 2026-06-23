# Twilio

Generated Source Runtime SDK scaffold for `twilio`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/twilio`
- Health endpoint: `/source-runtimes/health?source_id=twilio`
- Source health receipt: `sources/twilio/source_health_receipt.json`
- EvidenceCAS reference kind: `twilio.evidence_cas_reference`

## Families

- `accounts`, emits `twilio.accounts`, reads `/2010-04-01/Accounts.json`
- `keys`, emits `twilio.keys`, reads `/2010-04-01/Accounts/${config.account_sid}/Keys.json`
- `audit_events`, emits `twilio.audit_events`, reads `/v1/Events`

## Tests

- `go test ./sources/twilio ./internal/sourceprojection -count=1`
- `make catalog-check`
