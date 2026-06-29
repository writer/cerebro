# ClearBlade

Generated Source Runtime SDK scaffold for `clearblade`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/clearblade`
- Health endpoint: `/source-runtimes/health?source_id=clearblade`
- Source health receipt: `sources/clearblade/source_health_receipt.json`
- EvidenceCAS reference kind: `clearblade.evidence_cas_reference`

## Families

- `system`, emits `clearblade.system`, reads `/admin/platform/systems`
- `user`, emits `clearblade.user`, reads `/api/v/1/user`
- `deployment`, emits `clearblade.deployment`, reads `/api/v/3/${config.systemkey}/deployments`
- `connection`, emits `clearblade.connection`, reads `/api/v/4/devices/${config.systemkey}/connections`
- `platform_system`, emits `clearblade.platform_system`, reads `/admin/platform/systems/${config.systemkey}`
- `audit`, emits `clearblade.audit`, reads `/admin/audit`
- `timer`, emits `clearblade.timer`, reads `/api/v/3/code/${config.systemkey}/timers`
- `topic`, emits `clearblade.topic`, reads `/api/v/4/message/${config.systemkey}/topics`
- `trigger`, emits `clearblade.trigger`, reads `/api/v/3/code/${config.systemkey}/triggers`
- `session_user`, emits `clearblade.session_user`, reads `/admin/v/4/session/${config.systemkey}/user`
- `listindexe`, emits `clearblade.listindexe`, reads `/api/v/4/data/${config.systemkey}/${config.collectionname}/listindexes`
- `admin_audit`, emits `clearblade.admin_audit`, reads `/admin/audit/${config.systemkey}`

## Tests

- `go test ./sources/clearblade ./internal/sourceprojection -count=1`
- `make catalog-check`
