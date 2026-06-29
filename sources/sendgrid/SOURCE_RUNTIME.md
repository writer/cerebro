# SendGrid

Generated Source Runtime SDK scaffold for `sendgrid`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sendgrid`
- Health endpoint: `/source-runtimes/health?source_id=sendgrid`
- Source health receipt: `sources/sendgrid/source_health_receipt.json`
- EvidenceCAS reference kind: `sendgrid.evidence_cas_reference`

## Families

- `activity`, emits `sendgrid.activity`, reads `/access_settings/activity`
- `api_key`, emits `sendgrid.api_key`, reads `/api_keys`
- `group`, emits `sendgrid.group`, reads `/asm/groups`
- `invalid_email`, emits `sendgrid.invalid_email`, reads `/suppression/invalid_emails`

## Tests

- `go test ./sources/sendgrid ./internal/sourceprojection -count=1`
- `make catalog-check`
