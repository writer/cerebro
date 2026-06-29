# BulkSMS

Generated Source Runtime SDK scaffold for `bulksms`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bulksms`
- Health endpoint: `/source-runtimes/health?source_id=bulksms`
- Source health receipt: `sources/bulksms/source_health_receipt.json`
- EvidenceCAS reference kind: `bulksms.evidence_cas_reference`

## Families

- `webhook`, emits `bulksms.webhook`, reads `/webhooks`
- `relatedreceivedmessage`, emits `bulksms.relatedreceivedmessage`, reads `/messages/${config.id}/relatedReceivedMessages`
- `message`, emits `bulksms.message`, reads `/messages`
- `send`, emits `bulksms.send`, reads `/messages/send`

## Tests

- `go test ./sources/bulksms ./internal/sourceprojection -count=1`
- `make catalog-check`
