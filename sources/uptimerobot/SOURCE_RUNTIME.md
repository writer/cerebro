# UptimeRobot

Generated Source Runtime SDK scaffold for `uptimerobot`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/uptimerobot`
- Health endpoint: `/source-runtimes/health?source_id=uptimerobot`
- Source health receipt: `sources/uptimerobot/source_health_receipt.json`
- EvidenceCAS reference kind: `uptimerobot.evidence_cas_reference`

## Families

- `monitors`, emits `uptimerobot.monitors`, reads `/getMonitors`
- `alert_contacts`, emits `uptimerobot.alert_contacts`, reads `/getAlertContacts`
- `audit_events`, emits `uptimerobot.audit_events`, reads `/getAuditLog`

## Tests

- `go test ./sources/uptimerobot ./internal/sourceprojection -count=1`
- `make catalog-check`
