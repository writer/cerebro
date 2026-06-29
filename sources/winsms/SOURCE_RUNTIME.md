# WinSMS

Generated Source Runtime SDK scaffold for `winsms`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/winsms`
- Health endpoint: `/source-runtimes/health?source_id=winsms`
- Source health receipt: `sources/winsms/source_health_receipt.json`
- EvidenceCAS reference kind: `winsms.evidence_cas_reference`

## Families

- `subaccount`, emits `winsms.subaccount`, reads `/subaccounts`
- `incoming`, emits `winsms.incoming`, reads `/shortcode/incoming`
- `sms_incoming`, emits `winsms.sms_incoming`, reads `/sms/incoming`
- `optout`, emits `winsms.optout`, reads `/sms/incoming/optout`

## Tests

- `go test ./sources/winsms ./internal/sourceprojection -count=1`
- `make catalog-check`
