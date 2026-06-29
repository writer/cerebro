# Juniper Mist

Generated Source Runtime SDK scaffold for `mist`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mist`
- Health endpoint: `/source-runtimes/health?source_id=mist`
- Source health receipt: `sources/mist/source_health_receipt.json`
- EvidenceCAS reference kind: `mist.evidence_cas_reference`

## Families

- `call_event`, emits `mist.call_event`, reads `/api/v1/const/call_events`
- `sitegroup`, emits `mist.sitegroup`, reads `/api/v1/installer/orgs/${config.org_id}/sitegroups`
- `alarmtemplate`, emits `mist.alarmtemplate`, reads `/api/v1/installer/orgs/${config.org_id}/alarmtemplates`
- `secpolicy`, emits `mist.secpolicy`, reads `/api/v1/installer/orgs/${config.org_id}/secpolicies`

## Tests

- `go test ./sources/mist ./internal/sourceprojection -count=1`
- `make catalog-check`
