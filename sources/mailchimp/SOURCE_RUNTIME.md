# Mailchimp

Generated Source Runtime SDK scaffold for `mailchimp`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mailchimp`
- Health endpoint: `/source-runtimes/health?source_id=mailchimp`
- Source health receipt: `sources/mailchimp/source_health_receipt.json`
- EvidenceCAS reference kind: `mailchimp.evidence_cas_reference`

## Families

- `lists`, emits `mailchimp.lists`, reads `/lists`
- `members`, emits `mailchimp.members`, reads `/lists/${config.list_id}/members`
- `audit_events`, emits `mailchimp.audit_events`, reads `/activity-feed`

## Tests

- `go test ./sources/mailchimp ./internal/sourceprojection -count=1`
- `make catalog-check`
