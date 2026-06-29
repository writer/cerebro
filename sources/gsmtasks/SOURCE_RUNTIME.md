# GSMTasks

Generated Source Runtime SDK scaffold for `gsmtasks`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gsmtasks`
- Health endpoint: `/source-runtimes/health?source_id=gsmtasks`
- Source health receipt: `sources/gsmtasks/source_health_receipt.json`
- EvidenceCAS reference kind: `gsmtasks.evidence_cas_reference`

## Families

- `task_event`, emits `gsmtasks.task_event`, reads `/task_events/`
- `account`, emits `gsmtasks.account`, reads `/accounts/`
- `client_role`, emits `gsmtasks.client_role`, reads `/client_roles/`
- `formrule`, emits `gsmtasks.formrule`, reads `/formrules/`
- `notification`, emits `gsmtasks.notification`, reads `/notifications/`
- `device`, emits `gsmtasks.device`, reads `/devices/`
- `task_event_track`, emits `gsmtasks.task_event_track`, reads `/task_event_tracks/`
- `users_on_duty_log`, emits `gsmtasks.users_on_duty_log`, reads `/users_on_duty_log/`
- `account_role`, emits `gsmtasks.account_role`, reads `/account_roles/`
- `email`, emits `gsmtasks.email`, reads `/emails/`
- `user`, emits `gsmtasks.user`, reads `/users/`
- `notification_template`, emits `gsmtasks.notification_template`, reads `/notification_templates/`

## Tests

- `go test ./sources/gsmtasks ./internal/sourceprojection -count=1`
- `make catalog-check`
