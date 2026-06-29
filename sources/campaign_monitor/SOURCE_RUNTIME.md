# Campaign Monitor

Generated Source Runtime SDK scaffold for `campaign_monitor`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/campaign_monitor`
- Health endpoint: `/source-runtimes/health?source_id=campaign_monitor`
- Source health receipt: `sources/campaign_monitor/source_health_receipt.json`
- EvidenceCAS reference kind: `campaign_monitor.evidence_cas_reference`

## Families

- `users`, emits `campaign_monitor.users`, reads `/v1/users`
- `accounts`, emits `campaign_monitor.accounts`, reads `/v1/accounts`
- `records`, emits `campaign_monitor.records`, reads `/v1/records`
- `policies`, emits `campaign_monitor.policies`, reads `/v1/policies`
- `audit_events`, emits `campaign_monitor.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/campaign_monitor ./internal/sourceprojection -count=1`
- `make catalog-check`
