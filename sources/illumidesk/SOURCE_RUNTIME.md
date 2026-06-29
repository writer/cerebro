# IllumiDesk

Generated Source Runtime SDK scaffold for `illumidesk`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/illumidesk`
- Health endpoint: `/source-runtimes/health?source_id=illumidesk`
- Source health receipt: `sources/illumidesk/source_health_receipt.json`
- EvidenceCAS reference kind: `illumidesk.evidence_cas_reference`

## Families

- `team`, emits `illumidesk.team`, reads `/v1/teams/`
- `email`, emits `illumidesk.email`, reads `/v1/users/${config.user}/emails/`
- `notification`, emits `illumidesk.notification`, reads `/v1/${config.namespace}/notifications/`
- `deployment`, emits `illumidesk.deployment`, reads `/v1/${config.namespace}/projects/${config.project}/deployments/`
- `application`, emits `illumidesk.application`, reads `/v1/${config.namespace}/oauth/applications/`
- `group`, emits `illumidesk.group`, reads `/v1/teams/${config.team}/groups/`
- `entity`, emits `illumidesk.entity`, reads `/v1/${config.namespace}/notifications/entity/${config.entity}`
- `setting`, emits `illumidesk.setting`, reads `/v1/${config.namespace}/notifications/settings/`
- `profile`, emits `illumidesk.profile`, reads `/v1/users/profiles/`
- `server_size`, emits `illumidesk.server_size`, reads `/v1/servers/options/server-size/`
- `card`, emits `illumidesk.card`, reads `/v1/${config.namespace}/billing/cards/`
- `invoice`, emits `illumidesk.invoice`, reads `/v1/teams/${config.team}/billing/invoices/`

## Tests

- `go test ./sources/illumidesk ./internal/sourceprojection -count=1`
- `make catalog-check`
