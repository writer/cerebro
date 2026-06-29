# DRACOON

Generated Source Runtime SDK scaffold for `dracoon`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dracoon`
- Health endpoint: `/source-runtimes/health?source_id=dracoon`
- Source health receipt: `sources/dracoon/source_health_receipt.json`
- EvidenceCAS reference kind: `dracoon.evidence_cas_reference`

## Families

- `event_type`, emits `dracoon.event_type`, reads `/v4/provisioning/webhooks/event_types`
- `group`, emits `dracoon.group`, reads `/v4/groups`
- `user`, emits `dracoon.user`, reads `/v4/provisioning/customers/${config.customer_id}/users`
- `channel`, emits `dracoon.channel`, reads `/v4/config/info/notifications/channels`

## Tests

- `go test ./sources/dracoon ./internal/sourceprojection -count=1`
- `make catalog-check`
